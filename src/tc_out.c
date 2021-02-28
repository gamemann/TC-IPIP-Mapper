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

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif
#define offsetof(TYPE, MEMBER) ((uint16_t)&((TYPE *)0)->MEMBER)

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
};    

struct bpf_elf_map SEC("maps") mapping =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint32_t),
    .max_elem = 10000,
    .pinning = 2
};

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

    // Lookup the remote IP based off of the client IP (inner IP header's destination addresss).
    uint32_t *remoteip = bpf_map_lookup_elem(&mapping, &iph->daddr);

    // Check if the lookup was successful. If not, pass along.
    if (remoteip)
    {
        // Save the original remote IP for checksum recalculation.
        uint32_t oldremote = oiph->daddr;

        // Now that we know the lookup was successful, we want to change the outer IP header's destination address to the remote IP and recalculate the outer IP header's checksum.
        oiph->daddr = *remoteip;

        bpf_l3_csum_replace(skb, (sizeof(struct ethhdr) + offsetof(struct iphdr, daddr)), oldremote, oiph->daddr, sizeof(oiph->daddr));
    }

    return TC_ACT_OK;
}