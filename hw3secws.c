#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Razaq");
MODULE_DESCRIPTION("Basic Packet Filtering");
MODULE_VERSION("1");


// Netfilter hooks for relevant packet phases
static struct nf_hook_ops netfilter_ops_fw;

// A hook function used for the 3 relevan phases (In, Out, Through)
static unsigned int module_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    if (state->hook == NF_INET_LOCAL_IN || state->hook == NF_INET_LOCAL_OUT) {
        printk(KERN_INFO " *** Packet Dropped ***\n");
        return NF_DROP;
    } else if (state->hook == NF_INET_FORWARD) {
        printk(KERN_INFO "*** Packet Accepted ***");
        return NF_ACCEPT;
    }
    return NF_ACCEPT;
}


// Initialization function; handles error registering the hooks with cleanups and an indicative return value
static int __init fw_init(void) {
    int ret;
    printk(KERN_INFO "Loading hw1secws module...\n");
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

    nf_unregister_net_hook(&init_net, &netfilter_ops_in);
    nf_unregister_net_hook(&init_net, &netfilter_ops_out);
    nf_unregister_net_hook(&init_net, &netfilter_ops_fw);
}

module_init(fw_init);
module_exit(fw_exit);
