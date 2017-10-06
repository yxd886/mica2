#pragma once
#ifndef FIREWALL_H_
#define FIREWALL_H_

#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include "mica/nf/nf_common.h"
#include <vector>
#include <iostream>

struct firewall_state{
  uint8_t _tcp_flags;
	uint32_t _sent_seq;
	uint32_t _recv_ack;
	bool _pass;

	firewall_state():_tcp_flags(0),_sent_seq(0),_recv_ack(0),_pass(true){

	}
	firewall_state(uint8_t tcp_flags,uint32_t sent_seq,uint32_t recv_ack):_tcp_flags(tcp_flags),_sent_seq(sent_seq),_recv_ack(recv_ack),_pass(true){

	}
	void copy(struct firewall_state* c){
		_tcp_flags=c->_tcp_flags;
		_sent_seq=c->_sent_seq;
		_recv_ack=c->_recv_ack;
		_pass=c->_pass;
	}


};


class Firewall{
public:
	Firewall(struct rte_ring** worker2interface,struct rte_ring** interface2worker):
		_worker2interface(worker2interface),_interface2worker(interface2worker){

	  auto rules_config = ::mica::util::Config::load_file("firewall.json").get("rules");
	  for (size_t i = 0; i < rules_config.size(); i++) {
	    auto rule_conf = rules_config.get(i);
	    uint16_t src_port = ::mica::util::safe_cast<uint16_t>(
	    		rule_conf.get("src_port").get_uint64());
	    uint16_t dst_port = ::mica::util::safe_cast<uint16_t>(
	    		rule_conf.get("dst_port").get_uint64());

	    uint32_t src_addr = ::mica::network::NetworkAddress::parse_ipv4_addr(
	    		rule_conf.get("src_addr").get_str().c_str());
	    uint32_t dst_addr = ::mica::network::NetworkAddress::parse_ipv4_addr(
	    		rule_conf.get("dst_addr").get_str().c_str());
	    struct rule r(src_addr,dst_addr,src_port,dst_port);
	    rules.push_back(r);


	  }

	}

	struct firewall_state* update_state(struct firewall_state* firewall_state_ptr,struct tcp_hdr *tcp){


		struct firewall_state* return_state=new firewall_state(tcp->tcp_flags,tcp->sent_seq,tcp->recv_ack);
		return_state->_pass=firewall_state_ptr->_pass;
		return return_state;

	}

	void check_session(struct fivetuple* five,firewall_state* state){

		std::vector<rule>::iterator it;
		for(it==rules.begin();it!=rules.end();it++){
			if(five->_dst_addr==it->_dst_addr&&five->_dst_port==it->_dst_port&&five->_src_addr==it->_src_addr&&five->_src_port==it->_src_port){
				state->_pass=false;
			}
		}
		state->_pass=true;

	}

	bool state_changed(struct firewall_state* src,struct firewall_state* dst){
		if(src->_tcp_flags!=dst->_tcp_flags||src->_recv_ack!=dst->_recv_ack||src->_sent_seq!=dst->_sent_seq){
			return true;
		}
		return false;
	}
	void process_packet(struct rte_mbuf* rte_pkt){

		struct ipv4_hdr *iphdr;
		struct tcp_hdr *tcp;
    unsigned lcore_id;

    lcore_id = rte_lcore_id();
		iphdr = rte_pktmbuf_mtod_offset(rte_pkt,
                                       struct ipv4_hdr *,
                                       sizeof(struct ether_hdr));

    if (iphdr->next_proto_id==IPPROTO_TCP) {

			tcp = (struct tcp_hdr *)((unsigned char *)iphdr +
															sizeof(struct ipv4_hdr));

			struct fivetuple tuple(iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port,iphdr->next_proto_id);
			char* key = reinterpret_cast<char*>(&tuple);
			size_t key_length;
			key_length= sizeof(tuple);
			uint64_t key_hash;
			key_hash= hash(key, key_length);
			struct rte_ring_item item(key_hash,key_length,key);
			rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
			void* rev_item;
			rev_item=poll_interface2worker_ring(_interface2worker[lcore_id]);
			struct session_state* ses_state=nullptr;

			if(rev_item==nullptr){
				//new session
				ses_state= new session_state();
				ses_state->_action=WRITE;
				check_session(&tuple,&(ses_state->_firewall_state));

			}else{

				ses_state=&(((struct rte_ring_item*)rev_item)->_state);
			}

			struct firewall_state* fw_state=update_state(&(ses_state->_firewall_state),tcp);
			if(state_changed(&(ses_state->_firewall_state),fw_state)){
				item._state._action=WRITE;
				item._state._firewall_state.copy(fw_state);
				rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
			}

			if(ses_state->_firewall_state._pass==true){
				//pass
			}else{
				//drop
			}



    }


	}

	std::vector<rule> rules;
	struct rte_ring** _worker2interface;
	struct rte_ring** _interface2worker;

};


#endif
