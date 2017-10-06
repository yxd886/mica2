#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include <vector>
#include <iostream>
#include "mica/nf/firewall.h"
#include "mica/nf/load_balancer.h"


int main(int argc, const char* argv[]) {

	struct rte_ring* worker2interface[10];
	struct rte_ring* interface2worker[10];
	Firewall a(worker2interface,interface2worker);
	Load_balancer b(worker2interface,interface2worker,0);
	return 0;
}
