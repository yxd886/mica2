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



struct session_state{
	uint32_t _action;

	//firewall state:
	struct firewall_state _firewall_state;



	session_state():_action(READ),_firewall_state(){}

};

#endif
