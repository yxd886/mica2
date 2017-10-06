#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include <vector>
#include <iostream>

#define READ 0
#define WRITE 1

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

/*class ResponseHandler
    : public ::mica::datagram::ResponseHandlerInterface<Client> {
 public:
  void handle(Client::RequestDescriptor rd, Result result, const char* value,
              size_t value_length, const Argument& arg) {
  		_value=value;
  		_value_length=value_length;

  }

  const char* _value;
  size_t _value_length;
};*/

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

struct firewall_state{
  uint8_t _tcp_flags;
	uint32_t _sent_seq;
	uint32_t _recv_ack;
	bool _pass;

	firewall_state():_tcp_flags(0),_sent_seq(0),_recv_ack(0),_pass(true){

	}
	firewall_state(uint8_t tcp_flags,uint64_t sent_seq,uint32_t recv_ack):_tcp_flags(tcp_flags),_sent_seq(sent_seq),_recv_ack(recv_ack),_pass(true){

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


struct rte_ring_item{
	uint64_t _key_hash;
	size_t _key_length;
	char* _key;
	struct session_state _state;


  rte_ring_item(uint64_t key_hash,
  							  size_t key_length,
								char* key
             ) :
            	 _key_hash(key_hash),
							 _key_length(key_length),
							 _key(key),
							 _state()
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

/*struct Args {
  uint16_t lcore_id;
  ::mica::util::Config* config;
  Alloc* alloc;
  Client* client;
  double zipf_theta;
} __attribute__((aligned(128)));


int data_store_client_interface(){
	while(true){



	}
}

int worker_proc(void* arg) {
  auto args = reinterpret_cast<Args*>(arg);

  Client& client = *args->client;

  ::mica::util::lcore.pin_thread(args->lcore_id);

  printf("worker running on lcore %" PRIu16 "\n", args->lcore_id);

  client.probe_reachability();

  ResponseHandler rh;

  size_t num_items = 192 * 1048576;

  // double get_ratio = 0.95;
  double get_ratio = 0.50;

  uint32_t get_threshold = (uint32_t)(get_ratio * (double)((uint32_t)-1));

  ::mica::util::Rand op_type_rand(static_cast<uint64_t>(args->lcore_id) + 1000);
  ::mica::util::ZipfGen zg(num_items, args->zipf_theta,
                           static_cast<uint64_t>(args->lcore_id));
  ::mica::util::Stopwatch sw;
  sw.init_start();
  sw.init_end();

  uint64_t key_i;
  uint64_t key_hash;
  size_t key_length = sizeof(key_i);
  char* key = reinterpret_cast<char*>(&key_i);

  uint64_t value_i;
  size_t value_length = sizeof(value_i);
  char* value = reinterpret_cast<char*>(&value_i);

  bool use_noop = false;
  // bool use_noop = true;

  uint64_t last_handle_response_time = sw.now();
  // Check the response after sending some requests.
  // Ideally, packets per batch for both RX and TX should be similar.
  uint64_t response_check_interval = 20 * sw.c_1_usec();

  uint64_t seq = 0;
  while (true) {
    // Determine the operation type.
    uint32_t op_r = op_type_rand.next_u32();
    bool is_get = op_r <= get_threshold;

    // Generate the key.
    key_i = zg.next();
    key_hash = hash(key, key_length);

    uint64_t now = sw.now();
    while (!client.can_request(key_hash) ||
           sw.diff_in_cycles(now, last_handle_response_time) >=
               response_check_interval) {
      last_handle_response_time = now;
      client.handle_response(rh);
    }

    if (!use_noop) {
      if (is_get)
        client.get(key_hash, key, key_length);
      else {
        value_i = seq;
        client.set(key_hash, key, key_length, value, value_length, true);
      }
    } else {
      if (is_get)
        client.noop_read(key_hash, key, key_length);
      else {
        value_i = seq;
        client.noop_write(key_hash, key, key_length, value, value_length);
      }
    }

    seq++;
  }

  return 0;
}
*/
int main(int argc, const char* argv[]) {
	return 0;
}
