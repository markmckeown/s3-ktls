#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

BPF_HISTOGRAM(counter, u64);
const int RETURN_CODE = XDP_PASS;

int https_incoming_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    uint64_t network_header_offset = sizeof(*eth);
    if (data + network_header_offset > data_end)
    {
        return RETURN_CODE;
    }


    uint16_t h_proto = eth->h_proto;
    int protocol_index;

    // Only interested in IPv4
    if (h_proto != htons(ETH_P_IP))
    {
	    return RETURN_CODE;
    }

    uint64_t io_header_offset = sizeof(struct iphdr);
    if (data + network_header_offset  + io_header_offset > data_end) 
    {
	    return RETURN_CODE;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if (ip->protocol != IPPROTO_TCP)
    {
	    return RETURN_CODE;
    }
	
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) <= data_end)
    {
	u64 value = htons(tcp->source);
	if (value == 443) {
	    counter.increment(value);
	}
    }
      
    return XDP_PASS;
}
