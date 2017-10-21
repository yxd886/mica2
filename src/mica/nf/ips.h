#pragma once
#ifndef IPS_H_
#define IPS_H_

#include "mica/datagram/datagram_client.h"
#include "mica/util/lcore.h"
#include "mica/util/hash.h"
#include "mica/util/zipf.h"
#include "mica/network/dpdk.h"
#include "mica/nf/nf_common.h"
#include <vector>
#include <iostream>
#include "../util/aho-corasick/aho.h"
#include "../util/aho-corasick/util.h"
#include "../util/aho-corasick/fpp.h"
#include <stdlib.h>
#include <time.h>


#define MAX_MATCH 8192

/* A list of patterns matched by a packet */
struct mp_list_t {
	int num_match;
	uint16_t ptrn_id[MAX_MATCH];
};

/* Plain old API-call batching */
void process_batch(const struct aho_dfa *dfa_arr,
	const struct aho_pkt *pkts, struct mp_list_t *mp_list, struct ips_state* ips_state)
{
	int I, j;

	for(I = 0; I < BATCH_SIZE; I++) {
		int dfa_id = pkts[I].dfa_id;
		int len = pkts[I].len;
		struct aho_state *st_arr = dfa_arr[dfa_id].root;

		int state = ips_state->_state;

		for(j = 0; j < len; j++) {
			int count = st_arr[state].output.count;

			if(count != 0) {
				/* This state matches some patterns: copy the pattern IDs
				  *  to the output */
				int offset = mp_list[I].num_match;
				memcpy(&mp_list[I].ptrn_id[offset],
					st_arr[state].out_arr, count * sizeof(uint16_t));
				mp_list[I].num_match += count;
				ips_state->_alert=true;
				ips_state->_state=state;
				return;

			}
			int inp = pkts[I].content[j];
			state = st_arr[state].G[inp];
		}
		ips_state->_state=state;
	}


}

void ids_func(struct aho_ctrl_blk *cb,struct ips_state* state)
{
	int i, j;


	int id = cb->tid;
	struct aho_dfa *dfa_arr = cb->dfa_arr;
	struct aho_pkt *pkts = cb->pkts;
	int num_pkts = cb->num_pkts;

	/* Per-batch matched patterns */
	struct mp_list_t mp_list[BATCH_SIZE];
	for(i = 0; i < BATCH_SIZE; i++) {
		mp_list[i].num_match = 0;
	}

	/* Being paranoid about GCC optimization: ensure that the memcpys in
	  *  process_batch functions don't get optimized out */
	int matched_pat_sum = 0;

	//int tot_proc = 0;		/* How many packets did we actually match ? */
	//int tot_success = 0;	/* Packets that matched a DFA state */
	// tot_bytes = 0;		/* Total bytes matched through DFAs */

	for(i = 0; i < num_pkts; i += BATCH_SIZE) {
		process_batch(dfa_arr, &pkts[i], mp_list,state);

		for(j = 0; j < BATCH_SIZE; j++) {
			int num_match = mp_list[j].num_match;
			assert(num_match < MAX_MATCH);


			mp_list[j].num_match = 0;
		}
	}



}

struct aho_pkt * parse_pkt(struct rte_mbuf* rte_pkt, struct ips_state* state){
	struct aho_pkt  aho_pkt;
	aho_pkt.content=(uint8_t*)malloc(rte_pkt->buf_len);
	memcpy(aho_pkt.content,rte_pkt->buf_addr,rte_pkt->buf_len);
	aho_pkt.dfa_id=state->_dfa_id;
	aho_pkt.len=rte_pkt->buf_len;
	return &aho_pkt;
}


class IPS{
public:
    IPS(struct rte_ring** worker2interface,struct rte_ring** interface2worker):
		_worker2interface(worker2interface),_interface2worker(interface2worker),_drop(false){



    		int num_patterns, num_pkts, i;

        	int num_threads = 1;
        	assert(num_threads >= 1 && num_threads <= AHO_MAX_THREADS);

        	stats =(struct stat_t*)malloc(num_threads * sizeof(struct stat_t));
        	for(i = 0; i < num_threads; i++) {
        		stats[i].tput = 0;
        	}

        	struct aho_pattern *patterns;



        	/* Thread structures */
        	//pthread_t worker_threads[AHO_MAX_THREADS];


        	red_printf("State size = %lu\n", sizeof(struct aho_state));

        	/* Initialize the shared DFAs */
        	for(i = 0; i < AHO_MAX_DFA; i++) {
        		printf("Initializing DFA %d\n", i);
        		aho_init(&dfa_arr[i], i);
        	}

        	red_printf("Adding patterns to DFAs\n");
        	patterns = aho_get_patterns(AHO_PATTERN_FILE,
        		&num_patterns);

        	for(i = 0; i < num_patterns; i++) {
        		int dfa_id = patterns[i].dfa_id;
        		aho_add_pattern(&dfa_arr[dfa_id], &patterns[i], i);
        	}

        	red_printf("Building AC failure function\n");
        	for(i = 0; i < AHO_MAX_DFA; i++) {
        		aho_build_ff(&dfa_arr[i]);
        		aho_preprocess_dfa(&dfa_arr[i]);
        	}
    }





    void init_automataState(struct ips_state* state){
    	srand((unsigned)time(NULL));
    	state->_state=0;
    	state->_alert=false;
    	state->_dfa_id=rand()%AHO_MAX_DFA;
    }
    void ips_detect(struct rte_mbuf* rte_pkt, struct ips_state* state){

    	struct aho_pkt *pkts;
    	pkts = parse_pkt(rte_pkt, state);
       	struct aho_ctrl_blk worker_cb;



		worker_cb.stats = stats;
		worker_cb.tot_threads = 1;
		worker_cb.tid = 0;
		worker_cb.dfa_arr = dfa_arr;
		worker_cb.pkts = pkts;
		worker_cb.num_pkts = 1;

		ids_func(&worker_cb,state);


    }

	void process_packet(struct rte_mbuf* rte_pkt){


		if(DEBUG==1) printf("processing ips on core:%d\n",rte_lcore_id());

	    struct ipv4_hdr *iphdr;
	    struct tcp_hdr *tcp;
	    unsigned lcore_id;
	    _drop=false;

	    lcore_id = rte_lcore_id();
	    iphdr = rte_pktmbuf_mtod_offset(rte_pkt,
	            struct ipv4_hdr *,
	            sizeof(struct ether_hdr));

	    if (iphdr->next_proto_id!=IPPROTO_TCP){
		    //drop
	    	if(DEBUG==1) printf("not tcp pkt\n");
	        _drop=true;
	        return;
	    }else{

	    	tcp = (struct tcp_hdr *)((unsigned char *)iphdr +sizeof(struct ipv4_hdr));
	    	struct ips_state state(0);
	    	struct fivetuple tuple(iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port,iphdr->next_proto_id);

	       // printf("src_addr:%d ,iphdr->dst_addr:%d tcp->src_port:%d tcp->dst_port:%d\n ",iphdr->src_addr,iphdr->dst_addr,tcp->src_port,tcp->dst_port);


            //generate key based on five-tuples
	        char* key = reinterpret_cast<char*>(&tuple);
	        size_t key_length;
	        key_length= sizeof(tuple);
	        uint64_t key_hash;
	        key_hash= hash(key, key_length);
	        void* rev_item;
	        struct rte_ring_item item(key_hash,key_length,key);

	    	  if((tcp->tcp_flags&0x2)>>1==1){ //is A tcp syn

	    		    init_automataState(&state);


		            item._state._action=WRITE;
		            item._state._ips_state.copy(&state);
		            if(DEBUG==1)  printf("try to enqueue to _worker2interface[%d] \n",lcore_id);
		            rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
		            if(DEBUG==1)  printf("enqueue to _worker2interface[%d] completed\n",lcore_id);

			        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
			        rev_item=get_value(_interface2worker[lcore_id]);
			        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);


	    	  }else{

	  	        if(DEBUG==1)  printf("try to enqueue to _worker2interface[%d] \n",lcore_id);
	  	        rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
	  	        if(DEBUG==1)  printf("enqueue to _worker2interface[%d] completed\n",lcore_id);

	  	        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
	  	        rev_item=get_value(_interface2worker[lcore_id]);
	  	        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);
	  	        if(rev_item==nullptr){
		            item._state._action=WRITE;
		            item._state._ips_state.copy(&state);
		            if(DEBUG==1)  printf("try to enqueue to _worker2interface[%d] \n",lcore_id);
		            rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
		            if(DEBUG==1)  printf("enqueue to _worker2interface[%d] completed\n",lcore_id);

			        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
			        rev_item=get_value(_interface2worker[lcore_id]);
			        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);
			        return;
	  	        }
	  	        state._state=((struct rte_ring_item*)rev_item)->_state._ips_state._state;
	  	        state._alert=((struct rte_ring_item*)rev_item)->_state._ips_state._alert;
	  	        state._dfa_id=((struct rte_ring_item*)rev_item)->_state._ips_state._dfa_id;
	  	        if(state._alert){
	  	        	_drop=true;
	  	        	return;
	  	        }
				ips_detect(rte_pkt,&state);

	            item._state._action=WRITE;
	            item._state._ips_state.copy(&state);
	            if(DEBUG==1)  printf("try to enqueue to _worker2interface[%d] \n",lcore_id);
	            rte_ring_enqueue(_worker2interface[lcore_id],static_cast<void*>(&item));
	            if(DEBUG==1)  printf("enqueue to _worker2interface[%d] completed\n",lcore_id);

		        if(DEBUG==1)  printf("try to dequeue from _interface2worker[%d]\n",lcore_id);
		        rev_item=get_value(_interface2worker[lcore_id]);
		        if(DEBUG==1)  printf("dequeue from _interface2worker[%d] completed\n",lcore_id);
	  	        if(state._alert){
	  	        	_drop=true;
	  	        	return;
	  	        }


	    	  }

	    }


    }

	struct rte_ring** _worker2interface;
	struct rte_ring** _interface2worker;
	bool _drop;
	struct aho_dfa dfa_arr[AHO_MAX_DFA];
	struct stat_t *stats;

};


#endif
