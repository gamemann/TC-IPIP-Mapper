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

SEC("out")
int out_prog(struct __sk_buff *skb)
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

    // Lookup the remote IP based off of the client IP (inner IP header's destination addresss).
    uint32_t *remoteip = bpf_map_lookup_elem(&mapping, &iph->daddr);

    // Check if the lookup was successful. If not, pass along.
    if (remoteip)
    {
        // Save the original remote IP for checksum recalculation.
        uint32_t oldremote = oiph->daddr;

        // Now that we know the lookup was successful, we want to change the outer IP header's destination address to the remote IP and recalculate the outer IP header's checksum.
        oiph->daddr = *remoteip;
        uint32_t dest_ip = *remoteip;

        if (iph <= (struct iphdr *)data_end)
        {
                // Now that we know the lookup was successful, we want to change the outer IP header's destination address to the remote IP and recalculate the outer IP header's checksum.
                bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), &dest_ip, sizeof(__u32), 0);
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        eth = data;

        if (eth + 1 > (struct ethhdr *)data_end)
        {

                return TC_ACT_SHOT;
        }

        oiph = data + sizeof(struct ethhdr);

        if (oiph + 1 > (struct iphdr *)data_end)
        {
                return TC_ACT_SHOT;
        }

        iph = data + sizeof(struct ethhdr) + (oiph->ihl * 4);

        if (iph + 1 > (struct iphdr *)data_end)
        {
                return TC_ACT_SHOT;
        }

#ifdef DEBUG
        bpf_printk("[TC_MAPPER_OUT] Replacing remote from %lu to %lu.\n", oldremote, oiph->daddr);
#endif

        bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), oldremote, oiph->daddr, sizeof(oiph->daddr));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";