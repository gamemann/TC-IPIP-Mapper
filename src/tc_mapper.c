#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/types.h>
#include <inttypes.h>

#include <bpf_helpers.h>

#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#endif

//#define REPLACE_SOURCE_REMOTE 0
//#define REPLACE_SOURCE_WITH_INNER
//#define DEBUG


struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __uint(pinning, 1);
    __type(key, uint32_t);
    __type(value, uint32_t);
} mapping SEC(".maps");

#undef bpf_printk
#define bpf_printk(fmt, ...)                    \
({                                              \
    char ____fmt[] = fmt;                       \
    bpf_trace_printk(____fmt, sizeof(____fmt),  \
             ##__VA_ARGS__);                    \
})

SEC("mapper")
int mapper_prog(struct __sk_buff *skb)
{
    // Initialize packet data.
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Initialize Ethernet header.
    struct ethhdr *eth = data;

    if (unlikely(eth + 1 > (struct ethhdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // If not IPv4, pass along.
    if (eth->h_proto != htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    // Initialize (outer) IP header.
    struct iphdr *oiph = data + sizeof(struct ethhdr);

    if (unlikely(oiph + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // If the IP protocol isn't IPIP, pass along.
    if (oiph->protocol != IPPROTO_IPIP)
    {
        return TC_ACT_OK;
    }

    // Initialize (inner) IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr) + (oiph->ihl * 4);

    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        return TC_ACT_SHOT;
    }

    // Simply map the client IP (key) to the incoming remote IP (value).
    bpf_map_update_elem(&mapping, &iph->saddr, &oiph->saddr, BPF_ANY);

#ifdef DEBUG
    bpf_printk("[TC_MAPPER_IN] Mapping client %lu to %lu.\n", iph->saddr, oiph->saddr);
#endif


#ifdef REPLACE_SOURCE_REMOTE
    // Replace the outer IP header's source address with this.
    __be32 oldremote = oiph->saddr;
    #ifdef REPLACE_SOURCE_WITH_INNER
    oiph->saddr = iph->daddr;
    #else
    oiph->saddr = REPLACE_SOURCE_REMOTE;
    #endif

#ifdef DEBUG
    bpf_printk("[TC_MAPPER_IN] Replacing source IP %lu with %lu.\n", oldremote, oiph->saddr);
#endif    

    bpf_l3_csum_replace(skb, (sizeof(struct ethhdr) + offsetof(struct iphdr, daddr)), oldremote, oiph->daddr, sizeof(oiph->daddr));
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";