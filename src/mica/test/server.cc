#include "mica/datagram/datagram_server.h"
#include "mica/util/lcore.h"

struct DPDKConfig : public ::mica::network::BasicDPDKConfig {
  static constexpr bool kVerbose = true;
};

struct PartitionsConfig : public ::mica::processor::BasicPartitionsConfig {
  static constexpr bool kSkipPrefetchingForRecentKeyHashes = false;
  // static constexpr bool kVerbose = true;
};

struct DatagramServerConfig
    : public ::mica::datagram::BasicDatagramServerConfig {
  typedef ::mica::processor::Partitions<PartitionsConfig> Processor;
  typedef ::mica::network::DPDK<DPDKConfig> Network;
  // static constexpr bool kVerbose = true;
};

typedef ::mica::datagram::DatagramServer<DatagramServerConfig> Server;

int main() {
  ::mica::util::lcore.pin_thread(0);

  auto config = ::mica::util::Config::load_file("server.json");

  Server::DirectoryClient dir_client(config.get("dir_client"));

  DatagramServerConfig::Processor::Alloc alloc(config.get("alloc"));
  printf("alloc success\n");
  DatagramServerConfig::Processor processor(config.get("processor"), &alloc);
  printf("processor success\n");

  DatagramServerConfig::Network network(config.get("network"));
  printf("network success\n");
  network.start();
  printf("network start success\n");

  Server server(config.get("server"), &processor, &network, &dir_client);
  printf("server success\n");
  server.run();

  network.stop();

  return EXIT_SUCCESS;
}
