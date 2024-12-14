#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include "fw.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Razaq");
MODULE_DESCRIPTION("Basic Packet Filtering");
MODULE_VERSION("1");


// Netfilter hooks for relevant packet phases
static struct nf_hook_ops netfilter_ops_fw;

static rule_t RULES[2] = {
    {
        .rule_name = "telnet2_rule",
        .direction = DIRECTION_ANY,
        .src_ip = __constant_htonl(0x0A000101), // 10.0.1.1
        .src_prefix_mask = __constant_htonl(0xFFFFFF00), // 255.255.255.0
        .src_prefix_size = 24,
        .dst_ip = IP_ANY, // 0.0.0.0
        .dst_prefix_mask = IP_ANY, // 0.0.0.0
        .dst_prefix_size = 0,
        .src_port = __constant_htons(23), // Source port 23
        .dst_port = __constant_htons(1023), // Any port > 1023
        .protocol = PROT_TCP,
        .ack = ACK_YES,
        .action = NF_ACCEPT, // Accept packets
    },
    {
        .rule_name = "default",
        .direction = DIRECTION_ANY,
        .src_ip = IP_ANY,
        .src_prefix_mask = IP_ANY,
        .src_prefix_size = 0,
        .dst_ip = IP_ANY,
        .dst_prefix_mask = IP_ANY,
        .dst_prefix_size = 0,
        .src_port = __constant_htons(PORT_ANY),
        .dst_port = __constant_htons(PORT_ANY),
        .protocol = PROT_ANY,
        .ack = ACK_ANY,
        .action = NF_DROP, // Drop packets
    }
};

// A hook function used for the 3 relevant phases (In, Out, Through)
static unsigned int module_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    // Declare variables corresponding to rule_t fields
    unsigned int verdict = NF_DROP;
    struct iphdr *ip_header;
    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT; // If no IP header, accept the packet
    verdict = comp_packet_to_rules(skb, state);
    return verdict
}


static void extract_transport_fields(struct sk_buff *skb, __u8 protocol, __be16 *src_port, __be16 *dst_port, __u8 *ack) {
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;

    // Initialize output parameters
    *src_port = 0;
    *dst_port = 0;
    *ack = ACK_NO;

    // Extract transport-layer fields based on protocol
    if (protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        if (tcp_header) {
            *src_port = ntohs(tcp_header->source);
            *dst_port = ntohs(tcp_header->dest);
            *ack = (tcp_header->ack ? ACK_YES : ACK_NO);
        }
    } else if (protocol == IPPROTO_UDP) {
        udp_header = udp_hdr(skb);
        if (udp_header) {
            *src_port = ntohs(udp_header->source);
            *dst_port = ntohs(udp_header->dest);
        }
    }
}


static unsigned int comp_packet_to_rules(struct sk_buff *skb, const struct nf_hook_state *state) {
    // Declare variables corresponding to rule_t fields
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u8 ack = 0; // This will require parsing TCP headers
    struct iphdr *ip_header;
    direction_t direction; // Declare direction

    direction = strcmp(state->in->name, IN_NET_DEVICE_NAME) == 0 ? DIRECTION_IN : DIRECTION_OUT;

    // Extract the IP header from the packet
    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT; // If no IP header, accept the packet

    // Extract IP fields
    src_ip = ip_header->saddr;
    dst_ip = ip_header->daddr;
    protocol = ip_header->protocol;

    extract_transport_fields(skb, protocol, &src_port, &dst_port, &ack);

    // Debugging: Print extracted values with direction
    printk(KERN_INFO "Packet: direction=%s, src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, protocol=%u, ack=%u\n",
           direction == DIRECTION_IN ? "IN" : "OUT", &src_ip, &dst_ip, src_port, dst_port, protocol, ack);

    return NF_ACCEPT; // Placeholder: packet will be filtered later
}


// Initialization function; handles error registering the hooks with cleanups and an indicative return value
static int __init fw_init(void) {

    int ret;
    printk(KERN_INFO "Loading hw1secws module...!\n");
    printk(KERN_INFO "%s", RULES[0].rule_name);
    printk(KERN_INFO "%s", RULES[1].rule_name);
    // Set up the Netfilter hook for forwarding packets
    netfilter_ops_fw.hook = module_hook;
    netfilter_ops_fw.pf = PF_INET;
    netfilter_ops_fw.hooknum = NF_INET_FORWARD;
    netfilter_ops_fw.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &netfilter_ops_fw);
    if (ret) {
        printk(KERN_ERR "hw1secws: Failed to register forwarding hook. Error: %d\n", ret);
        return ret;
    }
    
    return 0;
}

static void __exit fw_exit(void) {
    printk(KERN_INFO "Removing hw1secws module...\n");

    nf_unregister_net_hook(&init_net, &netfilter_ops_fw);
}

module_init(fw_init);
module_exit(fw_exit);
