#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include <vector>

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
  		_value=value;
  		_value_length=value_length;

  }

  const char* _value;
  size_t _value_length;
};

struct rule{
public:
	rule(uint32_t src_addr,uint32_t dst_addr,uint16_t src_port,uint16_t dst_port):
		_src_addr(src_addr),_dst_addr(dst_addr),_src_port(src_port),_dst_port(dst_port){

	}
	uint32_t _src_addr;
	uint32_t _dst_addr;
	uint16_t _src_port;
	uint16_t _dst_port;
};

struct session_state{

};
class Firewall{
public:
	Firewall(){

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

	std::vector<rule> rules;

};

struct Args {
  uint16_t lcore_id;
  ::mica::util::Config* config;
  Alloc* alloc;
  Client* client;
  double zipf_theta;
} __attribute__((aligned(128)));

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

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    printf("%s ZIPF-THETA\n", argv[0]);
    return EXIT_FAILURE;
  }

  double zipf_theta = atof(argv[1]);

  ::mica::util::lcore.pin_thread(0);

  auto config = ::mica::util::Config::load_file("netbench.json");

  Alloc alloc(config.get("alloc"));

  DatagramClientConfig::Network network(config.get("network"));
  network.start();

  Client::DirectoryClient dir_client(config.get("dir_client"));

  Client client(config.get("client"), &network, &dir_client);
  client.discover_servers();

  uint16_t lcore_count =
      static_cast<uint16_t>(::mica::util::lcore.lcore_count());

  std::vector<Args> args(lcore_count);
  for (uint16_t lcore_id = 0; lcore_id < lcore_count; lcore_id++) {
    args[lcore_id].lcore_id = lcore_id;
    args[lcore_id].config = &config;
    args[lcore_id].alloc = &alloc;
    args[lcore_id].client = &client;
    args[lcore_id].zipf_theta = zipf_theta;
  }

  for (uint16_t lcore_id = 1; lcore_id < lcore_count; lcore_id++) {
    if (!rte_lcore_is_enabled(static_cast<uint8_t>(lcore_id))) continue;
    rte_eal_remote_launch(worker_proc, &args[lcore_id], lcore_id);
  }
  worker_proc(&args[0]);

  network.stop();

  return EXIT_SUCCESS;
}
