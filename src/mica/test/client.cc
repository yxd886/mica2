/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include <vector>
#include <map>
#include <iostream>
#include "mica/nf/firewall.h"
#include "mica/nf/load_balancer.h"
#include "mica/nf/nat.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

struct rte_ring* worker2interface[10];
struct rte_ring* interface2worker[10];


#if RTE_LOG_LEVEL >= RTE_LOG_DEBUG
#define L3FWDACL_DEBUG
#endif
#define DO_RFC_1812_CHECKS

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

#define MAX_JUMBO_PKT_LEN  9600

#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking into account memory for rx and tx hardware
 * rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a
 * minimum value of 8192
 */

#define NB_MBUF RTE_MAX(\
    (nb_ports * nb_rx_queue*RTE_TEST_RX_DESC_DEFAULT +  \
    nb_ports * nb_lcores * MAX_PKT_BURST +          \
    nb_ports * n_tx_queue * RTE_TEST_TX_DESC_DEFAULT +  \
    nb_lcores * MEMPOOL_CACHE_SIZE),            \
    (unsigned)8192)

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

#define NB_SOCKETS 8

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
static struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* mask of enabled ports */
static uint32_t enabled_port_mask;
static int promiscuous_on; /**< Ports set in promiscuous mode off by default. */
static int numa_on = 1; /**< NUMA is enabled by default. */

struct lcore_rx_queue {
    uint8_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024
struct lcore_params {
    uint8_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
    {0, 0, 2},
    {0, 1, 2},
    {0, 2, 2},
    {1, 0, 2},
    {1, 1, 2},
    {1, 2, 2},
    {2, 0, 2},
    {3, 0, 3},
    {3, 1, 3},
};

static struct lcore_params *lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) /
                sizeof(lcore_params_array_default[0]);

struct rte_eth_conf port_conf;





static struct rte_mempool *pktmbuf_pool[NB_SOCKETS];

/***********************start of ACL part******************************/
#ifdef DO_RFC_1812_CHECKS
static inline int
is_valid_ipv4_pkt(struct ipv4_hdr *pkt, uint32_t link_len);
#endif
static inline void
send_single_packet(struct rte_mbuf *m, uint8_t port);

#define MAX_ACL_RULE_NUM    100000
#define DEFAULT_MAX_CATEGORIES  1
#define L3FWD_ACL_IPV4_NAME "l3fwd-acl-ipv4"
#define L3FWD_ACL_IPV6_NAME "l3fwd-acl-ipv6"
#define ACL_LEAD_CHAR       ('@')
#define ROUTE_LEAD_CHAR     ('R')
#define COMMENT_LEAD_CHAR   ('#')
#define OPTION_CONFIG       "config"
#define OPTION_NONUMA       "no-numa"
#define OPTION_ENBJMO       "enable-jumbo"
#define OPTION_RULE_IPV4    "rule_ipv4"
#define OPTION_RULE_IPV6    "rule_ipv6"
#define OPTION_SCALAR       "scalar"
#define ACL_DENY_SIGNATURE  0xf0000000
#define RTE_LOGTYPE_L3FWDACL    RTE_LOGTYPE_USER3
#define acl_log(format, ...)    RTE_LOG(ERR, L3FWDACL, format, ##__VA_ARGS__)
#define uint32_t_to_char(ip, a, b, c, d) do {\
        *a = (unsigned char)(ip >> 24 & 0xff);\
        *b = (unsigned char)(ip >> 16 & 0xff);\
        *c = (unsigned char)(ip >> 8 & 0xff);\
        *d = (unsigned char)(ip & 0xff);\
    } while (0)
#define OFF_ETHHEAD (sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m) \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m) \
    rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

#define GET_CB_FIELD(in, fd, base, lim, dlm)    do {            \
    unsigned long val;                                      \
    char *end;                                              \
    errno = 0;                                              \
    val = strtoul((in), &end, (base));                      \
    if (errno != 0 || end[0] != (dlm) || val > (lim))       \
        return -EINVAL;                               \
    (fd) = (typeof(fd))val;                                 \
    (in) = end + 1;                                         \
} while (0)

/*
  * ACL rules should have higher priorities than route ones to ensure ACL rule
  * always be found when input packets have multi-matches in the database.
  * A exception case is performance measure, which can define route rules with
  * higher priority and route rules will always be returned in each lookup.
  * Reserve range from ACL_RULE_PRIORITY_MAX + 1 to
  * RTE_ACL_MAX_PRIORITY for route entries in performance measure
  */
#define ACL_RULE_PRIORITY_MAX 0x10000000

/*
  * Forward port info save in ACL lib starts from 1
  * since ACL assume 0 is invalid.
  * So, need add 1 when saving and minus 1 when forwarding packets.
  */
#define FWD_PORT_SHIFT 1

/*
 * Rule and trace formats definitions.
 */

enum {
    PROTO_FIELD_IPV4,
    SRC_FIELD_IPV4,
    DST_FIELD_IPV4,
    SRCP_FIELD_IPV4,
    DSTP_FIELD_IPV4,
    NUM_FIELDS_IPV4
};

/*
 * That effectively defines order of IPV4VLAN classifications:
 *  - PROTO
 *  - VLAN (TAG and DOMAIN)
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum {
    RTE_ACL_IPV4VLAN_PROTO,
    RTE_ACL_IPV4VLAN_VLAN,
    RTE_ACL_IPV4VLAN_SRC,
    RTE_ACL_IPV4VLAN_DST,
    RTE_ACL_IPV4VLAN_PORTS,
    RTE_ACL_IPV4VLAN_NUM
};



#define IPV6_ADDR_LEN   16
#define IPV6_ADDR_U16   (IPV6_ADDR_LEN / sizeof(uint16_t))
#define IPV6_ADDR_U32   (IPV6_ADDR_LEN / sizeof(uint32_t))

enum {
    PROTO_FIELD_IPV6,
    SRC1_FIELD_IPV6,
    SRC2_FIELD_IPV6,
    SRC3_FIELD_IPV6,
    SRC4_FIELD_IPV6,
    DST1_FIELD_IPV6,
    DST2_FIELD_IPV6,
    DST3_FIELD_IPV6,
    DST4_FIELD_IPV6,
    SRCP_FIELD_IPV6,
    DSTP_FIELD_IPV6,
    NUM_FIELDS_IPV6
};
enum {
    CB_FLD_SRC_ADDR,
    CB_FLD_DST_ADDR,
    CB_FLD_SRC_PORT_LOW,
    CB_FLD_SRC_PORT_DLM,
    CB_FLD_SRC_PORT_HIGH,
    CB_FLD_DST_PORT_LOW,
    CB_FLD_DST_PORT_DLM,
    CB_FLD_DST_PORT_HIGH,
    CB_FLD_PROTO,
    CB_FLD_USERDATA,
    CB_FLD_NUM,
};

//RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));
//RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

struct acl_search_t {
    const uint8_t *data_ipv4[MAX_PKT_BURST];
    struct rte_mbuf *m_ipv4[MAX_PKT_BURST];
    uint32_t res_ipv4[MAX_PKT_BURST];
    int num_ipv4;

    const uint8_t *data_ipv6[MAX_PKT_BURST];
    struct rte_mbuf *m_ipv6[MAX_PKT_BURST];
    uint32_t res_ipv6[MAX_PKT_BURST];
    int num_ipv6;
};

static struct{
    const char *rule_ipv4_name;
    const char *rule_ipv6_name;
    int scalar;
} parm_config;

const char cb_port_delim[] = ":";


struct lcore_conf {
    uint16_t n_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t n_tx_port;
    uint16_t tx_port_id[RTE_MAX_ETHPORTS];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
} __rte_cache_aligned;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];

/* Enqueue a single packet, and send burst if queue is filled */
static inline void
send_single_packet(struct rte_mbuf *m, uint8_t port)
{
    uint32_t lcore_id;
    struct lcore_conf *qconf;

    lcore_id = rte_lcore_id();

    qconf = &lcore_conf[lcore_id];
    rte_eth_tx_buffer(port, qconf->tx_queue_id[port],
            qconf->tx_buffer[port], m);
}



static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid, void* function_ptr )
{
    //printf("creating firewall\n");
	//
	Firewall* a=(Firewall*)function_ptr;
    struct ether_hdr *eth;
    void *tmp;
    unsigned dst_port;
    int sent;
    struct rte_eth_dev_tx_buffer *buffer;
    unsigned lcore_id;
    lcore_id = rte_lcore_id();

    dst_port = portid;
    eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

    /* 02:00:00:00:00:xx */
 //   tmp = &eth->d_addr.addr_bytes[0];
 //   *((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dst_port << 40);

    /* src addr */
   // ether_addr_copy(&l2fwd_ports_eth_addr[dst_port], &eth->s_addr);

    a->process_packet(m);
    if(a->_drop){
        rte_pktmbuf_free(m);
    }else{
        send_single_packet(m,portid);
    }


}


/* main processing loop */
static int
main_loop(__attribute__((unused)) void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m;
    unsigned lcore_id;
    uint64_t prev_tsc, diff_tsc, cur_tsc;
    int i, nb_rx;
    uint8_t portid, queueid;
    struct lcore_conf *qconf;
    int socketid;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1)
            / US_PER_S * BURST_TX_DRAIN_US;

    prev_tsc = 0;
    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];
    socketid = rte_lcore_to_socket_id(lcore_id);


    //load network function
    Firewall a(worker2interface,interface2worker);

    if (qconf->n_rx_queue == 0) {
        RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
        return 0;
    }

    RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

    for (i = 0; i < qconf->n_rx_queue; i++) {

        portid = qconf->rx_queue_list[i].port_id;
        queueid = qconf->rx_queue_list[i].queue_id;
        RTE_LOG(INFO, L3FWD,
            " -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n",
            lcore_id, portid, queueid);
    }

    while (1) {

        cur_tsc = rte_rdtsc();

        /*
         * TX burst queue drain
         */
        diff_tsc = cur_tsc - prev_tsc;
        if (unlikely(diff_tsc > drain_tsc)) {
            for (i = 0; i < qconf->n_tx_port; ++i) {
                portid = qconf->tx_port_id[i];
                rte_eth_tx_buffer_flush(portid,
                        qconf->tx_queue_id[portid],
                        qconf->tx_buffer[portid]);
            }
            prev_tsc = cur_tsc;
        }

        /*
         * Read packet from RX queues
         */
        for (i = 0; i < qconf->n_rx_queue; ++i) {

            portid = qconf->rx_queue_list[i].port_id;
            queueid = qconf->rx_queue_list[i].queue_id;
            nb_rx = rte_eth_rx_burst(portid, queueid,
                pkts_burst, MAX_PKT_BURST);

            if (nb_rx > 0) {
                //
                for (int j = 0; j < nb_rx; j++) {
                    m = pkts_burst[j];
                    rte_prefetch0(rte_pktmbuf_mtod(m, void *));
                    l2fwd_simple_forward(m, portid,static_cast<void*>(&a));


                }
            }
        }
    }
}

static int
check_lcore_params(void)
{
    uint8_t queue, lcore;
    uint16_t i;
    int socketid;

    for (i = 0; i < nb_lcore_params; ++i) {
        queue = lcore_params[i].queue_id;
        if (queue >= MAX_RX_QUEUE_PER_PORT) {
            printf("invalid queue number: %hhu\n", queue);
            return -1;
        }
        lcore = lcore_params[i].lcore_id;
        if (!rte_lcore_is_enabled(lcore)) {
            printf("error: lcore %hhu is not enabled in "
                "lcore mask\n", lcore);
            return -1;
        }
        socketid = rte_lcore_to_socket_id(lcore);
        if (socketid != 0 && numa_on == 0) {
            printf("warning: lcore %hhu is on socket %d "
                "with numa off\n",
                lcore, socketid);
        }
    }
    return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
    unsigned portid;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        portid = lcore_params[i].port_id;

        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("port %u is not enabled in port mask\n", portid);
            return -1;
        }
        if (portid >= nb_ports) {
            printf("port %u is not present on the board\n", portid);
            return -1;
        }
    }
    return 0;
}

static uint8_t
get_port_n_rx_queues(const uint8_t port)
{
    int queue = -1;
    uint16_t i;

    for (i = 0; i < nb_lcore_params; ++i) {
        if (lcore_params[i].port_id == port &&
                lcore_params[i].queue_id > queue)
            queue = lcore_params[i].queue_id;
    }
    return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
    uint16_t i, nb_rx_queue;
    uint8_t lcore;

    for (i = 0; i < nb_lcore_params; ++i) {
        lcore = lcore_params[i].lcore_id;
        nb_rx_queue = lcore_conf[lcore].n_rx_queue;
        if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
            printf("error: too many queues (%u) for lcore: %u\n",
                (unsigned)nb_rx_queue + 1, (unsigned)lcore);
            return -1;
        } else {
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
                lcore_params[i].port_id;
            lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
                lcore_params[i].queue_id;
            lcore_conf[lcore].n_rx_queue++;
        }
    }
    return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
    printf("%s [EAL options] -- -p PORTMASK -P"
        "--"OPTION_RULE_IPV4"=FILE"
        "--"OPTION_RULE_IPV6"=FILE"
        "  [--"OPTION_CONFIG" (port,queue,lcore)[,(port,queue,lcore]]"
        "  [--"OPTION_ENBJMO" [--max-pkt-len PKTLEN]]\n"
        "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
        "  -P : enable promiscuous mode\n"
        "  --"OPTION_CONFIG": (port,queue,lcore): "
        "rx queues configuration\n"
        "  --"OPTION_NONUMA": optional, disable numa awareness\n"
        "  --"OPTION_ENBJMO": enable jumbo frame"
        " which max packet len is PKTLEN in decimal (64-9600)\n"
        "  --"OPTION_RULE_IPV4"=FILE: specify the ipv4 rules entries "
        "file. "
        "Each rule occupy one line. "
        "2 kinds of rules are supported. "
        "One is ACL entry at while line leads with character '%c', "
        "another is route entry at while line leads with "
        "character '%c'.\n"
        "  --"OPTION_RULE_IPV6"=FILE: specify the ipv6 rules "
        "entries file.\n"
        "  --"OPTION_SCALAR": Use scalar function to do lookup\n",
        prgname, ACL_LEAD_CHAR, ROUTE_LEAD_CHAR);
}

static int
parse_max_pkt_len(const char *pktlen)
{
    char *end = NULL;
    unsigned long len;

    /* parse decimal string */
    len = strtoul(pktlen, &end, 10);
    if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (len == 0)
        return -1;

    return len;
}

static int
parse_portmask(const char *portmask)
{
    char *end = NULL;
    unsigned long pm;

    /* parse hexadecimal string */
    pm = strtoul(portmask, &end, 16);
    if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
        return -1;

    if (pm == 0)
        return -1;

    return pm;
}

static int
parse_config(const char *q_arg)
{
    char s[256];
    const char *p, *p0 = q_arg;
    char *end;
    enum fieldnames {
        FLD_PORT = 0,
        FLD_QUEUE,
        FLD_LCORE,
        _NUM_FLD
    };
    unsigned long int_fld[_NUM_FLD];
    char *str_fld[_NUM_FLD];
    int i;
    unsigned size;

    nb_lcore_params = 0;

    while ((p = strchr(p0, '(')) != NULL) {
        ++p;
        if ((p0 = strchr(p, ')')) == NULL)
            return -1;

        size = p0 - p;
        if (size >= sizeof(s))
            return -1;

        snprintf(s, sizeof(s), "%.*s", size, p);
        if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') !=
                _NUM_FLD)
            return -1;
        for (i = 0; i < _NUM_FLD; i++) {
            errno = 0;
            int_fld[i] = strtoul(str_fld[i], &end, 0);
            if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
                return -1;
        }
        if (nb_lcore_params >= MAX_LCORE_PARAMS) {
            printf("exceeded max number of lcore params: %hu\n",
                nb_lcore_params);
            return -1;
        }
        lcore_params_array[nb_lcore_params].port_id =
            (uint8_t)int_fld[FLD_PORT];
        lcore_params_array[nb_lcore_params].queue_id =
            (uint8_t)int_fld[FLD_QUEUE];
        lcore_params_array[nb_lcore_params].lcore_id =
            (uint8_t)int_fld[FLD_LCORE];
        ++nb_lcore_params;
    }
    lcore_params = lcore_params_array;
    return 0;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
    int opt, ret;
    char **argvopt;
    int option_index;
    char *prgname = argv[0];
    static struct option lgopts[] = {
        {OPTION_CONFIG, 1, 0, 0},
        {OPTION_NONUMA, 0, 0, 0},
        {OPTION_ENBJMO, 0, 0, 0},
        {OPTION_RULE_IPV4, 1, 0, 0},
        {OPTION_RULE_IPV6, 1, 0, 0},
        {OPTION_SCALAR, 0, 0, 0},
        {NULL, 0, 0, 0}
    };

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "p:P",
                lgopts, &option_index)) != EOF) {

        switch (opt) {
        /* portmask */
        case 'p':
            enabled_port_mask = parse_portmask(optarg);
            if (enabled_port_mask == 0) {
                printf("invalid portmask\n");
                print_usage(prgname);
                return -1;
            }
            break;
        case 'P':
            printf("Promiscuous mode selected\n");
            promiscuous_on = 1;
            break;

        /* long options */
        case 0:
            if (!strncmp(lgopts[option_index].name,
                    OPTION_CONFIG,
                    sizeof(OPTION_CONFIG))) {
                ret = parse_config(optarg);
                if (ret) {
                    printf("invalid config\n");
                    print_usage(prgname);
                    return -1;
                }
            }

            if (!strncmp(lgopts[option_index].name,
                    OPTION_NONUMA,
                    sizeof(OPTION_NONUMA))) {
                printf("numa is disabled\n");
                numa_on = 0;
            }

            if (!strncmp(lgopts[option_index].name,
                    OPTION_ENBJMO, sizeof(OPTION_ENBJMO))) {
                struct option lenopts = {
                    "max-pkt-len",
                    required_argument,
                    0,
                    0
                };

                printf("jumbo frame is enabled\n");
                port_conf.rxmode.jumbo_frame = 1;

                /*
                 * if no max-pkt-len set, then use the
                 * default value ETHER_MAX_LEN
                 */
                if (0 == getopt_long(argc, argvopt, "",
                        &lenopts, &option_index)) {
                    ret = parse_max_pkt_len(optarg);
                    if ((ret < 64) ||
                        (ret > MAX_JUMBO_PKT_LEN)) {
                        printf("invalid packet "
                            "length\n");
                        print_usage(prgname);
                        return -1;
                    }
                    port_conf.rxmode.max_rx_pkt_len = ret;
                }
                printf("set jumbo frame max packet length "
                    "to %u\n",
                    (unsigned int)
                    port_conf.rxmode.max_rx_pkt_len);
            }

            if (!strncmp(lgopts[option_index].name,
                    OPTION_RULE_IPV4,
                    sizeof(OPTION_RULE_IPV4)))
                parm_config.rule_ipv4_name = optarg;

            if (!strncmp(lgopts[option_index].name,
                    OPTION_RULE_IPV6,
                    sizeof(OPTION_RULE_IPV6))) {
                parm_config.rule_ipv6_name = optarg;
            }

            if (!strncmp(lgopts[option_index].name,
                    OPTION_SCALAR, sizeof(OPTION_SCALAR)))
                parm_config.scalar = 1;


            break;

        default:
            print_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind-1] = prgname;

    ret = optind-1;
    optind = 0; /* reset getopt lib */
    return ret;
}

static void
print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
    char buf[ETHER_ADDR_FMT_SIZE];
    ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s", name, buf);
}

static int
init_mem(unsigned nb_mbuf)
{
    int socketid;
    unsigned lcore_id;
    char s[64];

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        if (numa_on){
            socketid = rte_lcore_to_socket_id(lcore_id);
            printf("socketid= %d\n",socketid);
        }else
            socketid = 0;

        if (socketid >= NB_SOCKETS) {
            rte_exit(EXIT_FAILURE,
                "Socket %d of lcore %u is out of range %d\n",
                socketid, lcore_id, NB_SOCKETS);
        }
        if (pktmbuf_pool[socketid] == NULL) {
            snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
            printf("s: %s, nb_mbuf:%d,MEMPOOL_CACHE_SIZE:%d, RTE_MBUF_DEFAULT_BUF_SIZE: %d\n",s,nb_mbuf,MEMPOOL_CACHE_SIZE,RTE_MBUF_DEFAULT_BUF_SIZE);
            pktmbuf_pool[socketid] =
                rte_pktmbuf_pool_create(s, nb_mbuf,
                    MEMPOOL_CACHE_SIZE, 0,
                    RTE_MBUF_DEFAULT_BUF_SIZE,
                    socketid);
            if (pktmbuf_pool[socketid] == NULL)
                rte_exit(EXIT_FAILURE,
                    "Cannot init mbuf pool on socket %d，errno: %s\n",
                    socketid,rte_strerror(rte_errno));
            else
                printf("Allocated mbuf pool on socket %d\n",
                    socketid);
        }
    }
    return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("\nChecking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for (portid = 0; portid < port_num; portid++) {
            if ((port_mask & (1 << portid)) == 0)
                continue;
            memset(&link, 0, sizeof(link));
            rte_eth_link_get_nowait(portid, &link);
            /* print link status if flag set */
            if (print_flag == 1) {
                if (link.link_status)
                    printf("Port %d Link Up - speed %u "
                        "Mbps - %s\n", (uint8_t)portid,
                        (unsigned)link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                    ("full-duplex") : ("half-duplex\n"));
                else
                    printf("Port %d Link Down\n",
                        (uint8_t)portid);
                continue;
            }
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
            rte_delay_ms(CHECK_INTERVAL);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
            print_flag = 1;
            printf("done\n");
        }
    }
}


void prepare_rte_ring(){

	for(int i=0; i<10; i++){


		worker2interface[i] = rte_ring_create(("worker2interface"+std::to_string(i)).c_str(), 1024,
                        rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);

		interface2worker[i] = rte_ring_create(("interface2worker"+std::to_string(i)).c_str(), 1024,
                        rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	}

}

void port_config(){
    port_conf.rxmode.mq_mode    = ETH_MQ_RX_RSS,
    port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN,
    port_conf.rxmode.split_hdr_size = 0,
    port_conf.rxmode.header_split   = 0, /**< Header Split disabled */
    port_conf.rxmode.hw_ip_checksum = 1, /**< IP checksum offload enabled */
    port_conf.rxmode.hw_vlan_filter = 0, /**< VLAN filtering disabled */
    port_conf.rxmode.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
    port_conf.rxmode.hw_strip_crc   = 0, /**< CRC stripped by hardware */
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL,
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
    ETH_RSS_TCP | ETH_RSS_SCTP,
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
}

//for mica


int
main(int argc, char **argv)
{
    struct lcore_conf *qconf;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    int ret;
    unsigned nb_ports;
    uint16_t queueid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t portid, nb_rx_queue, queue, socketid;
    //::mica::util::lcore.pin_thread(0);
    port_config();


    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    /* parse application arguments (after the EAL ones) */
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

    if (check_lcore_params() < 0)
        rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

    nb_ports = rte_eth_dev_count(); //leave one port for mica
    printf("number of port: %d\n",nb_ports);

    if (check_port_config(nb_ports) < 0)
        rte_exit(EXIT_FAILURE, "check_port_config failed\n");

    /* Add ACL rules and route entries, build trie */
    //if (app_acl_init() < 0)
    //    rte_exit(EXIT_FAILURE, "app_acl_init failed\n");

    nb_lcores = rte_lcore_count();
    prepare_rte_ring();

    /* initialize all ports */
    for (portid = 0; portid < nb_ports; portid++) {
        /* skip ports that are not enabled */
        if ((enabled_port_mask & (1 << portid)) == 0) {
            printf("\nSkipping disabled port %d\n", portid);
            continue;
        }

        /* init port */
        printf("Initializing port %d ... ", portid);
        fflush(stdout);

        nb_rx_queue = get_port_n_rx_queues(portid);
        n_tx_queue = nb_lcores;
        if (n_tx_queue > MAX_TX_QUEUE_PER_PORT)
            n_tx_queue = MAX_TX_QUEUE_PER_PORT;
        printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
            nb_rx_queue, (unsigned)n_tx_queue);
        ret = rte_eth_dev_configure(portid, nb_rx_queue,
                    (uint16_t)n_tx_queue, &port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "Cannot configure device: err=%d, port=%d\n",
                ret, portid);

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        print_ethaddr(" Address:", &ports_eth_addr[portid]);
        printf(", ");

        /* init memory */
        ret = init_mem(NB_MBUF);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "init_mem failed\n");

        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            /* Initialize TX buffers */
            qconf = &lcore_conf[lcore_id];
            qconf->tx_buffer[portid] = (struct rte_eth_dev_tx_buffer *)rte_zmalloc_socket("tx_buffer",
                    RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                    rte_eth_dev_socket_id(portid));
            if (qconf->tx_buffer[portid] == NULL)
                rte_exit(EXIT_FAILURE, "Can't allocate tx buffer for port %u\n",
                        (unsigned) portid);

            rte_eth_tx_buffer_init(qconf->tx_buffer[portid], MAX_PKT_BURST);
        }

        /* init one TX queue per couple (lcore,port) */
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            if (numa_on)
                socketid = (uint8_t)
                    rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("txq=%u,%d,%d ", lcore_id, queueid, socketid);
            fflush(stdout);

            rte_eth_dev_info_get(portid, &dev_info);
            txconf = &dev_info.default_txconf;
            if (port_conf.rxmode.jumbo_frame)
                txconf->txq_flags = 0;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
                             socketid, txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "rte_eth_tx_queue_setup: err=%d, "
                    "port=%d\n", ret, portid);

            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
        printf("\n");
    }

    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;
        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        fflush(stdout);
        /* init RX queues */
        for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;

            if (numa_on)
                socketid = (uint8_t)
                    rte_lcore_to_socket_id(lcore_id);
            else
                socketid = 0;

            printf("rxq=%d,%d,%d ", portid, queueid, socketid);
            fflush(stdout);

            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
                    socketid, NULL,
                    pktmbuf_pool[socketid]);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                    "rte_eth_rx_queue_setup: err=%d,"
                    "port=%d\n", ret, portid);
        }
    }

    printf("\n");

    /* start ports */
    for (portid = 0; portid < nb_ports; portid++) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;

        /* Start device */
        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                "rte_eth_dev_start: err=%d, port=%d\n",
                ret, portid);

        /*
         * If enabled, put device in promiscuous mode.
         * This allows IO forwarding mode to forward packets
         * to itself through 2 cross-connected  ports of the
         * target machine.
         */
        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    check_all_ports_link_status((uint8_t)nb_ports, enabled_port_mask);

    /* launch per-lcore init on every lcore */
    //rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);
    int num=rte_lcore_count();

    //lcore_id=0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id){
        rte_eal_remote_launch(main_loop, NULL, lcore_id);
    }
  //  rte_eal_mp_remote_launch(main_loop, NULL, CALL_MASTER);

    printf("master core ready to run mica client\n");

    //start mica client
    auto config = ::mica::util::Config::load_file("client.json");

    DatagramClientConfig::Network network(config.get("network"),true);
    network.start();
    Client::DirectoryClient dir_client(config.get("dir_client"));

    Client client(config.get("client"), &network, &dir_client);
    client.discover_servers();
    int master = rte_get_master_lcore();
    ::mica::util::lcore.pin_thread(master);

    client.probe_reachability();
    std::map<uint64_t,uint64_t> lcore_map;
    ResponseHandler rh(&lcore_map,worker2interface,interface2worker);

    size_t num_items = 192 * 1048576;

    // double get_ratio = 0.95;
    double get_ratio = 0.50;

    uint32_t get_threshold = (uint32_t)(get_ratio * (double)((uint32_t)-1));


    ::mica::util::Rand op_type_rand(static_cast<uint64_t>(master) + 1000);
    ::mica::util::ZipfGen zg(num_items, 0.5,
                     static_cast<uint64_t>(master));
    ::mica::util::Stopwatch sw;
    sw.init_start();
    sw.init_end();

    uint64_t key_i;
    uint64_t key_hash;
    size_t key_length = sizeof(key_i);
    char* key = reinterpret_cast<char*>(&key_i);

    size_t value_length;
    char* value;
    size_t rcv_value_length;
    char* rcv_value;


    // bool use_noop = true;

    uint64_t last_handle_response_time = sw.now();
    // Check the response after sending some requests.
    // Ideally, packets per batch for both RX and TX should be similar.
    uint64_t response_check_interval = 20 * sw.c_1_usec();


    void* dequeue_output[1];
    struct rte_ring_item* rcv_item;
    struct session_state* rcv_state;
    struct session_state* hash_rcv_state;

    while (true) {
        // Determine the operation type.
        uint32_t op_r = op_type_rand.next_u32();
        bool is_get = op_r <= get_threshold;

        // Generate the key.
    	uint64_t now = sw.now();
        while (!client.can_request(key_hash) ||
                sw.diff_in_cycles(now, last_handle_response_time) >=
                response_check_interval) {
            last_handle_response_time = now;
            printf("master handle_response now\n");
            client.handle_response(rh);
            printf("master handle_response finished\n");
        }


        RTE_LCORE_FOREACH_SLAVE(lcore_id){
            //    if(lcore_id!=num)
            int flag=1;
            //printf("dequeueing from ring %d\n",lcore_id);
            flag = rte_ring_sc_dequeue(worker2interface[lcore_id], dequeue_output);
            if(flag==0){
              //receive msg from workers

            	printf("received a msg from worker2interface[%d]\n",lcore_id);

                rcv_item=((struct rte_ring_item*)dequeue_output[0]);
                key=rcv_item->_key;
                key_length=rcv_item->_key_length;
                key_hash=rcv_item->_key_hash;
                rcv_state=&(rcv_item->_state);

                lcore_map[key_hash]=lcore_id;

                if(rcv_state->_action==READ){
                    //get
                	printf("READING FROM SERVER\n");
                	printf("key_hash:%d, key_length:%d, key:0x%x\n",key_hash,key_length,key);
                	client.get(key_hash, key, key_length);

                }else if(rcv_state->_action==WRITE){
                  //set
                	printf("WRITE TO SERVER\n");
                    value_length= sizeof(rcv_item->_state);
                    value= reinterpret_cast<char*>(rcv_state);
                    client.set(key_hash, key, key_length, value, value_length, true);

                }else{
                	printf("unrecognized action: %d\n",rcv_state->_action);
                }


            }else{
            	//printf("nothing in worker2interface[%d]\n",lcore_id);
            }

        }

    }

    return 0;
}
