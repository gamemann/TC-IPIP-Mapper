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

// TC has its own map definition.
struct bpf_elf_map 
{
    uint32_t type;
    uint32_t size_key;
    uint32_t size_value;
    uint32_t max_elem;
    uint32_t flags;
    uint32_t id;
    uint32_t pinning;
    uint32_t inner_id;
    uint32_t inner_idx;
};    

struct bpf_elf_map SEC("maps") mapping =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint32_t),
    .max_elem = 10000,
    .pinning = 2
};

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

#ifdef REPLACE_SOURCE_REMOTE
    // Replace the outer IP header's source address with this.
    __be32 oldremote = oiph->saddr;

    oiph->saddr = REPLACE_SOURCE_REMOTE;
    
    bpf_l3_csum_replace(skb, (sizeof(struct ethhdr) + offsetof(struct iphdr, daddr)), oldremote, oiph->daddr, sizeof(oiph->daddr));
#endif

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";