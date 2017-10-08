#pragma once
#ifndef MICA_NF_COMMON_H_
#define MICA_NF_COMMON_H_


#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include "mica/nf/nf_state.h"
#include <vector>
#include <iostream>



typedef ::mica::alloc::HugeTLBFS_SHM Alloc;

struct DPDKConfig : public ::mica::network::BasicDPDKConfig {
  static constexpr bool kVerbose = true;
};

struct DatagramClientConfig
    : public ::mica::datagram::BasicDatagramClientConfig {
  typedef ::mica::network::DPDK<DPDKConfig> Network;
  // static constexpr bool kSkipRX = true;
  // static constexpr bool kIgnoreServerPartition = true;
  // static constexpr bool kVerbose = true;
};

typedef ::mica::datagram::DatagramClient<DatagramClientConfig> Client;

typedef ::mica::table::Result Result;

template <typename T>
static uint64_t hash(const T* key, size_t key_length) {
  return ::mica::util::hash(key, key_length);
}

class ResponseHandler
    : public ::mica::datagram::ResponseHandlerInterface<Client> {
 public:
  void handle(Client::RequestDescriptor rd, Result result, const char* value,
              size_t value_length, const Argument& arg) {
    (void)rd;
    (void)result;
    (void)value;
    (void)value_length;
    (void)arg;
    _value=value;
    _value_length=value_length;

  }
  char* _value;
  size_t _value_length;


};

struct rule{
public:

	uint32_t _src_addr;
	uint32_t _dst_addr;
	uint16_t _src_port;
	uint16_t _dst_port;
	rule(uint32_t src_addr,uint32_t dst_addr,uint16_t src_port,uint16_t dst_port):
		_src_addr(src_addr),_dst_addr(dst_addr),_src_port(src_port),_dst_port(dst_port){

	}

};








struct rte_ring_item{
    uint64_t _key_hash;
    size_t _key_length;
    char* _key;
    struct session_state _state;


    rte_ring_item(uint64_t key_hash,size_t key_length,char* key) :
        _key_hash(key_hash),
        _key_length(key_length),
        _key(key),
        _state()
        {}
    rte_ring_item(uint64_t key_hash,size_t key_length,char* key,struct session_state& dst) :
        _key_hash(key_hash),
        _key_length(key_length),
        _key(key),
        _state(dst)
        {}
};



void* poll_interface2worker_ring(struct rte_ring* interface2worker_ring){
    int aggressive_poll_attemps = 50;
    int flag = 0;
    void* dequeue_output[1];

    for(int i=0; i<aggressive_poll_attemps; i++){
        flag = rte_ring_sc_dequeue(interface2worker_ring, dequeue_output);

        if(flag != 0){
            continue;
        }
        else{
            return dequeue_output[0];
        }
    }

    for(;;){
        flag = rte_ring_sc_dequeue(interface2worker_ring, dequeue_output);

        if(flag != 0){
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        else{
            return dequeue_output[0];
        }
    }
}

void* get_value(struct rte_ring* interface2worker_ring){
    return poll_interface2worker_ring(interface2worker_ring);
}

struct fivetuple{
public:
    uint32_t _src_addr;
    uint32_t _dst_addr;
    uint16_t _src_port;
    uint16_t _dst_port;
    uint8_t _next_proto_id;
	fivetuple(uint32_t src_addr,uint32_t dst_addr,uint16_t src_port,uint16_t dst_port,uint8_t next_proto_id):
	    _src_addr(src_addr),_dst_addr(dst_addr),_src_port(src_port),_dst_port(dst_port),_next_proto_id(next_proto_id){

	}


};




#endif
