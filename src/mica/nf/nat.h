#pragma once
#ifndef MICA_NAT_H_
#define MICA_NAT_H_


#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include "mica/nf/nf_common.h"
#include <vector>
#include <iostream>
#include <stdlib.h>
#include <time.h>


std::string ip_lists[64]={"192.168.122.131","192.168.122.132","192.168.122.133","192.168.122.134",
                "192.168.122.135","192.168.122.136","192.168.122.137","192.168.122.138",
                "192.168.122.139","192.168.122.140","192.168.122.141","192.168.122.142"};
uint16_t port_lists[64]={10012,10013,10014,10015,10016,10017,10018,10019,10020,10021,10022,10023,10024,10025,10026,10027,10028};

class NAT{
public:
    NAT(struct rte_ring** worker2interface,struct rte_ring** interface2worker,uint32_t cluster_id):
        _worker2interface(worker2interface),_interface2worker(interface2worker),_cluster_id(cluster_id),_drop(false){

    }


    void form_list(uint64_t backend_list_bit){
        _ip_list.clear();
        for (uint32_t i=0;i<sizeof(backend_list_bit);i++){
            uint64_t t=backend_list_bit&0x1;
            if(t==1){
                _ip_list.push_back(mica::network::NetworkAddress::parse_ipv4_addr(ip_lists[i].c_str()));
                _port_list.push_back(port_lists[i]);
            }

            backend_list_bit=backend_list_bit>>1;
        }
    }

    void select_ip_port(uint32_t* ip,uint16_t* port){
        srand((unsigned)time(nullptr));
        long unsigned int index=(long unsigned int)rand()%_ip_list.size();
        *port=_port_list[index];
        *ip=_ip_list[index];
        return;
    }

    void update_packet_header(uint32_t ip, uint16_t port,struct rte_mbuf* pkt){
        struct ipv4_hdr *iphdr;
        struct tcp_hdr *tcp;
        iphdr = rte_pktmbuf_mtod_offset(pkt,
                struct ipv4_hdr *,
                sizeof(struct ether_hdr));
        tcp = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
        iphdr->dst_addr=ip;
        tcp->dst_port=port;
        return;
    }

    void process_packet(struct rte_mbuf* rte_pkt){
        struct ipv4_hdr *iphdr;
        struct tcp_hdr *tcp;
        unsigned lcore_id;
        void* rev_item;
        _drop=false;
        struct session_state* ses_state=nullptr;

        lcore_id = rte_lcore_id();
        iphdr = rte_pktmbuf_mtod_offset(rte_pkt,
                struct ipv4_hdr *,
                sizeof(struct ether_hdr));

        if (iphdr->next_proto_id!=IPPROTO_TCP){
            //drop
            _drop=true;
            return;
        }else{

            tcp = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
            char* key=nullptr;
            size_t key_length;
            uint64_t key_hash;
            struct fivetuple tuple(iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port,iphdr->next_proto_id);
            key= reinterpret_cast<char*>(&tuple);
            key_length= sizeof(tuple);
            key_hash= hash(key, key_length);
            struct rte_ring_item item(key_hash,key_length,key);
            rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
            rev_item=get_value(_interface2worker[lcore_id]);
            if(rev_item==nullptr){
            //ip,port is null
                key= reinterpret_cast<char*>(&_cluster_id);
                key_length= sizeof(_cluster_id);
                key_hash= hash(key, key_length);
                struct rte_ring_item item1(key_hash,key_length,key);
                rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item1));
                rev_item=nullptr;
                rev_item=get_value(_interface2worker[lcore_id]);
                if(rev_item==nullptr){
                    //_cluster doesn't includes any dst.
                    std::cout<<"_cluster doesn't includes any dst"<<std::endl;
                    exit(-1);
                }else{

                    //select proper ip and port
                    ses_state=&(((struct rte_ring_item*)rev_item)->_state);
                    uint64_t ip_port_list_bit=ses_state->_nat_state._ip_port_list;
                    form_list(ip_port_list_bit);
                    uint32_t select_ip=0;
                    uint16_t select_port=0;
                    select_ip_port(&select_ip,&select_port);

                    //Write hash table(tuple, (ip,port))
                    key= reinterpret_cast<char*>(&tuple);
                    key_length= sizeof(tuple);
                    key_hash= hash(key, key_length);
                    struct rte_ring_item item2(key_hash,key_length,key);
                    item2._state._action=WRITE;
                    item2._state._nat_state._dst_ip_addr=select_ip;
                    item2._state._nat_state._dst_port=select_port;
                    rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item2));
    		        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
    		        rev_item=get_value(_interface2worker[lcore_id]);
    		        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);

                    //Write hash table(reverse_tuple, (p.ip,p.port))
                    struct fivetuple reverse_tuple(select_ip,iphdr->src_addr,select_port,tcp->src_port,iphdr->next_proto_id);
                    key= reinterpret_cast<char*>(&reverse_tuple);
                    key_length= sizeof(reverse_tuple);
                    key_hash= hash(key, key_length);
                    struct rte_ring_item item3(key_hash,key_length,key);
                    item3._state._action=WRITE;
                    item3._state._nat_state._dst_ip_addr=iphdr->src_addr;
                    item3._state._nat_state._dst_port=tcp->src_port;
                    rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item2));

    		        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
    		        rev_item=get_value(_interface2worker[lcore_id]);
    		        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);

                    update_packet_header(select_ip,select_port,rte_pkt);
                }

            }else{

                ses_state=&(((struct rte_ring_item*)rev_item)->_state);
                update_packet_header(ses_state->_nat_state._dst_ip_addr,ses_state->_nat_state._dst_port,rte_pkt);

            }


            //To do: send packet.
            return;



        }
    }



struct rte_ring** _worker2interface;
struct rte_ring** _interface2worker;
uint32_t _cluster_id;
std::vector<uint32_t> _ip_list;
std::vector<uint16_t> _port_list;
bool _drop;
};

#endif
