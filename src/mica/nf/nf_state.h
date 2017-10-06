#pragma once
#ifndef MICA_NF_STATE_H_
#define MICA_NF_STATE_H_

#define READ 0
#define WRITE 1

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

struct server_load{
    uint32_t _ip_addr;
    uint32_t current_load;
    server_load():_ip_addr(0),current_load(0){}
};

struct load_balancer_state{
    uint32_t _dst_ip_addr;
    uint64_t _backend_list;

    load_balancer_state():_dst_ip_addr(0),_backend_list(0){

    }

    void copy(struct load_balancer_state* c){
        _dst_ip_addr=c->_dst_ip_addr;
        _backend_list=c->_backend_list;

    }


};



struct session_state{
    uint32_t _action;

    //firewall state:
    struct firewall_state _firewall_state;
    struct load_balancer_state _load_balancer_state;
    session_state():_action(READ),_firewall_state(),_load_balancer_state(){}

};

#endif
