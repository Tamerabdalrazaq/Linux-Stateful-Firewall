// Integrating sysfs
// Integrated two sysfs devices

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/inet.h>
#include "fw.h"
#include <linux/klist.h>
#include <linux/jiffies.h> // For timestamp in jiffies
#include <linux/slab.h> // For kmalloc and kfree
#include <linux/fs.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Razaq");
MODULE_DESCRIPTION("Basic Packet Filtering");
MODULE_VERSION("1");

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
struct device *log_device;
static char buffer[256]; // Internal buffer for the device
static int buffer_size = 0; // Current size of the data in the buffer

// Define packet_log struct
struct packet_log {
    log_row_t log_object;       // The log entry object
    struct klist_node node;     // Node for inclusion in the klist
};

// Define the static klist for packet logs
static struct klist packet_logs = KLIST_INIT(packet_logs, NULL, NULL);
    // Finalize the iterator
static int logs_num = 0;

// Netfilter hooks for relevant packet phases
static struct nf_hook_ops netfilter_ops_fw;

// static rule_t RULES[3] = {
//     {
//         .rule_name = "telnet2_rule",
//         .direction = DIRECTION_ANY,
//         .src_ip = __constant_htonl(0x0A000101), // 10.0.1.1
//         .src_prefix_mask = __constant_htonl(0xFFFFFF00), // 255.255.255.0
//         .src_prefix_size = 24,
//         .dst_ip = IP_ANY, // 0.0.0.0
//         .dst_prefix_mask = IP_ANY, // 0.0.0.0
//         .dst_prefix_size = 0,
//         .src_port = __constant_htons(23), // Source port 23
//         .dst_port = __constant_htons(1023), // Any port > 1023
//         .protocol = PROT_TCP,
//         .ack = ACK_YES,
//         .action = NF_ACCEPT, // Accept packets
//     },
//     {
//         .rule_name = "ICMP Test",
//         .direction = DIRECTION_IN,
//         .src_ip = __constant_htonl(0x0a010101), // 10.0.1.1
//         .src_prefix_mask = __constant_htonl(0xFFFFFF00), // 255.255.255.0
//         .src_prefix_size = 24,
//         .dst_ip = IP_ANY, // 0.0.0.0
//         .dst_prefix_mask = IP_ANY, // 0.0.0.0
//         .dst_prefix_size = 0,
//         .src_port = __constant_htons(2048),
//         .dst_port = __constant_htons(0),
//         .protocol = PROT_ICMP,
//         .ack = ACK_ANY,
//         .action = NF_ACCEPT, // Accept packets
//     },
//     {
//         .rule_name = "default",
//         .direction = DIRECTION_ANY,
//         .src_ip = IP_ANY,
//         .src_prefix_mask = IP_ANY,
//         .src_prefix_size = 0,
//         .dst_ip = IP_ANY,
//         .dst_prefix_mask = IP_ANY,
//         .dst_prefix_size = 0,
//         .src_port = __constant_htons(PORT_ANY),
//         .dst_port = __constant_htons(PORT_ANY),
//         .protocol = PROT_ANY,
//         .ack = ACK_ANY,
//         .action = NF_DROP, // Drop packets
//     }
// };

static int RULES_COUNT = 0;
static rule_t* FW_RULES;


static void ip_to_string(__be32 ip, char *buffer) {
    unsigned char *bytes = (unsigned char *)&ip;
    snprintf(buffer, 16, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void print_fw_rules(void) {
    char src_ip_str[16];
    char dst_ip_str[16];
    int i;

    printk(KERN_INFO "Firewall Rules:\n");

    for (i = 0; i < RULES_COUNT; i++) {
        rule_t *rule = &FW_RULES[i];

        ip_to_string(rule->src_ip, src_ip_str);
        ip_to_string(rule->dst_ip, dst_ip_str);

        printk(KERN_INFO "Rule %d:\n", i + 1);
        printk(KERN_INFO "  Name: %s\n", rule->rule_name);
        printk(KERN_INFO "  Direction: %d\n", rule->direction);
        printk(KERN_INFO "  Source IP: %s/%d\n", src_ip_str, rule->src_prefix_size);
        printk(KERN_INFO "  Destination IP: %s/%d\n", dst_ip_str, rule->dst_prefix_size);
        printk(KERN_INFO "  Source Port: %u\n", ntohs(rule->src_port));
        printk(KERN_INFO "  Destination Port: %u\n", ntohs(rule->dst_port));
        printk(KERN_INFO "  Protocol: %u\n", rule->protocol);
        printk(KERN_INFO "  ACK: %u\n", rule->ack);
        printk(KERN_INFO "  Action: %u\n", rule->action);
    }
}


ssize_t display(struct device *dev, struct device_attribute *attr, char *buf) 
{
    int i;
    int len = 0; // Tracks the total length written into the buffer

    // Iterate over each rule and append its details to the buffer
    for (i = 0; i < RULES_COUNT; i++) {
        rule_t *rule = &FW_RULES[i];

        // Add each field of the rule in a readable format
        len += scnprintf(buf + len, PAGE_SIZE - len,
                         "%s %d %pI4/%d %pI4/%d %d %d %d %d %d\n",
                         rule->rule_name,
                         rule->direction,
                         &rule->src_ip, rule->src_prefix_size,
                         &rule->dst_ip, rule->dst_prefix_size,
                         rule->src_port,
                         rule->dst_port,
                         rule->protocol,
                         rule->ack,
                         rule->action);
        // Check if the buffer is full
        if (len >= PAGE_SIZE)
            break;
    }

    return len;
}


// Helper function to parse IP/prefix into IP, mask, and size
static int parse_ip_prefix(const char *ip_prefix, __be32 *ip, __be32 *mask, __u8 *prefix_size) {
    char ip_str[16];
    int prefix;
    if(strcmp(ip_prefix, "any") == 0){
        *prefix_size = (__u8)0;
        *mask = (IP_ANY);
        *ip = (IP_ANY);
    } else {
        if (sscanf(ip_prefix, "%15[^/]/%d", ip_str, &prefix) != 2) {
            return -EINVAL; // Invalid input
        }

        *prefix_size = (__u8)prefix;
        *mask = htonl(~0 << (32 - prefix));
        *ip = in_aton(ip_str);
    }

    return 0;
}



size_t get_rules_number(const char *buf, size_t count) {
    size_t rows = 0;
    size_t i;

    // Count the number of rows based on newline characters
    for (i = 0; i < count; i++) {
        if (buf[i] == '\n') {
            rows++;
        }
    }
    return rows;
}


static int parse_rule(const char *rule_str, rule_t *rule) {
    char src_ip_prefix[32], dst_ip_prefix[32], src_port_str[10], dst_port_str[10];
    char direction_str[10], protocol_str[10], ack_str[10], action_str[10];
    int src_port, dst_port;
    int successful_scans = sscanf(rule_str, "%19s %9s %31s %31s %9s %9s %9s %9s %9s",
               rule->rule_name, direction_str, src_ip_prefix, dst_ip_prefix,
               protocol_str, src_port_str, dst_port_str, ack_str, action_str);
    if (successful_scans != 9) {
                    printk(KERN_ALERT "Invalid rule string - Parsed  %d/9 fields", successful_scans);
                    printk(KERN_INFO "String: %s.\n", rule_str);
        return -EINVAL;
    }

    // Parse direction
    if (strcmp(direction_str, "in") == 0) {
        rule->direction = DIRECTION_IN;
    } else if (strcmp(direction_str, "out") == 0) {
        rule->direction = DIRECTION_OUT;
    } else if(strcmp(direction_str, "any") == 0){
        rule->direction = DIRECTION_ANY;
    } else {
        printk(KERN_CRIT "ERROR IN Direction");
        return -EINVAL;
    }

    // Parse IP prefixes
    if (parse_ip_prefix(src_ip_prefix, &rule->src_ip, &rule->src_prefix_mask, &rule->src_prefix_size) < 0 ||
        parse_ip_prefix(dst_ip_prefix, &rule->dst_ip, &rule->dst_prefix_mask, &rule->dst_prefix_size) < 0) {
        printk(KERN_CRIT "ERROR IN Rule Parsing IP Prefix.");
        return -EINVAL;
    }

    // Parse ports
    if (strcmp(protocol_str, "any") == 0) {
        rule->protocol = PROT_ANY;
    } else if (strcmp(protocol_str, "TCP") == 0) {
        rule->protocol = PROT_TCP;
    } else if (strcmp(protocol_str, "UDP") == 0) {
        rule->protocol = PROT_UDP;
    } else if (strcmp(protocol_str, "ICMP") == 0) {
        rule->protocol = PROT_ICMP;
    } else {
        // Undefined behaviour in the assignemnet
        printk(KERN_CRIT "ERROR IN Rule Protocol.");
        rule->protocol = -EINVAL;;
    }

    if (strcmp(src_port_str, "any") == 0) {
        rule->src_port = PORT_ANY;
    } else if (strcmp(src_port_str, ">1023") == 0){
        rule->src_port = PORT_ABOVE_1023;
    } else {
        rule->src_port = htons((__be16)src_port);
    }

    if (strcmp(dst_port_str, "any") == 0) {
        rule->dst_port = PORT_ANY;
    } else if (strcmp(dst_port_str, ">1023") == 0){
        rule->dst_port = PORT_ABOVE_1023;
    } else {
        rule->dst_port = htons((__be16)dst_port);
    }

    // Parse ACK
    if (strcmp(ack_str, "yes") == 0) {
        rule->ack = ACK_YES;
    } else if (strcmp(ack_str, "no") == 0) {
        rule->ack = ACK_NO;
    } else if (strcmp(ack_str, "any") == 0) {
        rule->ack = ACK_ANY;
    } else {
        printk(KERN_CRIT "ERROR IN Rule ACK Bit.");
        return -EINVAL;;
    }

    // Parse action
    if (strcmp(action_str, "accept") == 0) {
        rule->action = NF_ACCEPT;
    } else if (strcmp(action_str, "drop") == 0) {
        rule->action = NF_DROP;
    } else {
        printk(KERN_CRIT "ERROR IN Rule Decision.");
        return -EINVAL;
    }

    return 0;
}



ssize_t modify(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    char *rules_str, *line, *save_ptr;
    int i = 0;
    int num_of_rules = get_rules_number(buf, count);
    FW_RULES = kmalloc_array(num_of_rules, sizeof(rule_t), GFP_KERNEL);

    // Allocate memory for parsing
    rules_str = kmalloc(count + 1, GFP_KERNEL);
    if (!rules_str) {
        return -ENOMEM;
    }

    strncpy(rules_str, buf, count);
    rules_str[count] = '\0';

    // Split input into lines
    for (line = strsep(&rules_str, "\n"); line != NULL && i < num_of_rules + 1; line = strsep(&rules_str, "\n")) {
        if (parse_rule(line, &FW_RULES[i]) < 0) {
            printk(KERN_ALERT "ERROR IN Rule Parsing.");
            if (rules_str) {
                printk(KERN_INFO "Freeing rules_str: %p\n", rules_str); // Log pointer before freeing
                kfree(rules_str);                                      // Free memory
                rules_str = NULL;                                      // Prevent use-after-free
            } else {
                printk(KERN_WARNING "Attempt to free NULL rules_str pointer.\n");
            }
            return -EINVAL;
        }
        i++;
    }

    RULES_COUNT = i;
    if (rules_str) {
        kfree(rules_str);                                      // Free memory
    } else {
        printk(KERN_WARNING "Attempt to free NULL rules_str pointer.\n");
    }
    return count;
}

ssize_t reset_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
    struct klist_iter iter;
    struct packet_log *plog;
    struct klist_node *knode;

    // Initialize the iterator
    klist_iter_init(&packet_logs, &iter);

    // Iterate over the klist and remove each node
    while ((knode = klist_next(&iter)))
    {
        plog = container_of(knode, struct packet_log, node);
        klist_del(&plog->node);
        // Free the memory of the container structure
        kfree(plog);
    }

    klist_iter_exit(&iter);
    logs_num = 0;
    printk(KERN_INFO "Packet logs have been reset.\n");
    return count;
}

ssize_t my_read(struct file *filp, char __user *user_buf, size_t count, loff_t *f_pos)
{
    char *kernel_buf;
    size_t buf_size = 4096; // Allocate a buffer large enough to hold logs
    size_t offset = 0;
    struct klist_iter iter;
    struct packet_log *plog;
    struct klist_node *knode;
    char log_entry[256]; // Temporary buffer for each log entry
    int written;
    log_row_t *log;

    // Allocate kernel buffer
    kernel_buf = kmalloc(buf_size, GFP_KERNEL);
    if (!kernel_buf)
        return -ENOMEM;

    // Initialize the klist iterator
    klist_iter_init(&packet_logs, &iter);

    // Iterate over the klist
    while ((knode = klist_next(&iter)))
    {
        plog = container_of(knode, struct packet_log, node);
        log = &plog->log_object;

        // Format the log entry
        written = snprintf(log_entry, sizeof(log_entry), "%lu %pI4 %pI4 %u %u %u %u %d %u\n",
                           log->timestamp,
                           &log->src_ip, &log->dst_ip,
                           ntohs(log->src_port), ntohs(log->dst_port),
                           log->protocol, log->action, log->reason, log->count);

        // Check if we have enough space in the buffer
        if (offset + written >= buf_size)
            break;

        // Copy the formatted log entry into the kernel buffer
        strncpy(kernel_buf + offset, log_entry, written);
        offset += written;
    }

    // Finalize the klist iterator
    klist_iter_exit(&iter);

    // Check if there's anything to read based on *f_pos
    if (*f_pos >= offset)
    {
        kfree(kernel_buf);
        return 0; // EOF
    }

    // Copy data to user space, starting from *f_pos
    written = min(count, offset - *f_pos);
    if (copy_to_user(user_buf, kernel_buf + *f_pos, written))
    {
        kfree(kernel_buf);
        return -EFAULT;
    }

    // Update the file position
    *f_pos += written;

    // Free kernel buffer
    kfree(kernel_buf);

    return written;
}


void print_packet_logs(void) {
    struct klist_iter iter;
    struct klist_node *knode;
    struct packet_log *entry;

    printk(KERN_INFO "=== Printing Packet Logs ===\n");

    // Initialize the iterator for the klist
    klist_iter_init(&packet_logs, &iter);

    // Iterate over the klist
    while ((knode = klist_next(&iter))) {
        // Retrieve the parent structure from the node
        entry = container_of(knode, struct packet_log, node);

        // Print the log object details
        printk(KERN_INFO
               "Log Entry: Timestamp=%lu, Protocol=%u, Action=%u, "
               "Src_IP=%pI4, Dst_IP=%pI4, Src_Port=%u, Dst_Port=%u, "
               "Reason=%u, Count=%u\n",
               entry->log_object.timestamp,
               entry->log_object.protocol,
               entry->log_object.action,
               &entry->log_object.src_ip,
               &entry->log_object.dst_ip,
               ntohs(entry->log_object.src_port),
               ntohs(entry->log_object.dst_port),
               entry->log_object.reason,
               entry->log_object.count);
    }

    // Exit the iterator
    klist_iter_exit(&iter);

    printk(KERN_INFO "=== End of Packet Logs ===\n");
}


void add_or_update_log_entry(log_row_t *new_entry) {
    struct klist_iter iter;
    struct klist_node *knode;
    struct packet_log *existing_entry;

    int found = 0;

    // Initialize an iterator for the klist
    klist_iter_init(&packet_logs, &iter);

    // Iterate over the klist to find a matching entry
    while ((knode = klist_next(&iter))) {
        existing_entry = container_of(knode, struct packet_log, node);

        // Check if the existing entry matches the new_entry's fields
        if (existing_entry->log_object.src_ip == new_entry->src_ip &&
            existing_entry->log_object.dst_ip == new_entry->dst_ip &&
            existing_entry->log_object.src_port == new_entry->src_port &&
            existing_entry->log_object.dst_port == new_entry->dst_port &&
            existing_entry->log_object.protocol == new_entry->protocol) {
            
            // Match found: update timestamp and increment count
            existing_entry->log_object.timestamp = new_entry->timestamp;
            existing_entry->log_object.count++;
            found = 1;
            break;
        }
    }

    // Exit the iterator
    klist_iter_exit(&iter);

    if (!found) {
        // No match found: create a new entry and add it to the klist
        struct packet_log *new_log = kmalloc(sizeof(struct packet_log), GFP_KERNEL);
        if (!new_log)
            return; // Handle memory allocation failure

        // Copy the new_entry into the new log_object
        memcpy(&new_log->log_object, new_entry, sizeof(log_row_t));

        // Add the new log entry to the klist
        klist_add_tail(&new_log->node, &packet_logs);
        logs_num += 1;
    }
}


static void extract_transport_fields(struct sk_buff *skb, __u8 protocol, __be16 *src_port, __be16 *dst_port, __u8 *ack, int* is_christmas_packet) { 
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;

    // Initialize output parameters
    *src_port = 0;
    *dst_port = 0;
    *ack = ACK_NO;
    *is_christmas_packet = 0; // Default to false

    // Extract transport-layer fields based on protocol
    if (protocol == PROT_TCP) {
        tcp_header = tcp_hdr(skb);
        if (tcp_header) {
            *src_port = ntohs(tcp_header->source);
            *dst_port = ntohs(tcp_header->dest);
            *ack = (tcp_header->ack ? ACK_YES : ACK_NO);

            // Check if the packet is a Christmas tree packet
            if (tcp_header->fin && tcp_header->urg && tcp_header->psh) {
                *is_christmas_packet = 1; // Mark as true
            }
        }
    } else if (protocol == PROT_UDP) {
        udp_header = udp_hdr(skb);
        if (udp_header) {
            *src_port = ntohs(udp_header->source);
            *dst_port = ntohs(udp_header->dest);
        }
    } else if (protocol == PROT_ICMP) {
        icmp_header = icmp_hdr(skb);
        if (icmp_header) {
            *src_port = icmp_header->type; // Use type as src_port equivalent
            *dst_port = icmp_header->code; // Use code as dst_port equivalent
        }
    } else{

    }
}

static unsigned int comp_packet_to_rules(struct sk_buff *skb, const struct nf_hook_state *state) {
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u8 ack = 0;
    struct iphdr *ip_header;
    direction_t direction;
    size_t i;
    int is_christmas_packet = 0;
    log_row_t log_entry;

    memset(&log_entry, 0, sizeof(log_row_t)); // Initialize to zero
    direction = strcmp(state->in->name, IN_NET_DEVICE_NAME) == 0 ? DIRECTION_IN : DIRECTION_OUT;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    src_ip = ip_header->saddr;
    dst_ip = ip_header->daddr;
    protocol = ip_header->protocol;

    if (protocol != PROT_ICMP &&  protocol != PROT_TCP && protocol != PROT_ICMP)
        return NF_ACCEPT;

    extract_transport_fields(skb, protocol, &src_port, &dst_port, &ack, &is_christmas_packet);

    log_entry.timestamp = jiffies;           // Use jiffies as the timestamp
    log_entry.protocol = protocol;          // Protocol extracted from the IP header
    log_entry.src_ip = src_ip;              // Source IP from the packet
    log_entry.dst_ip = dst_ip;              // Destination IP from the packet
    log_entry.src_port = src_port;          // Source port from transport fields
    log_entry.dst_port = dst_port;          // Destination port from transport fields
    log_entry.count = 1;                    // Initial hit count       
           
    // Compare packet to rules
    if (is_christmas_packet == 0){
        for (i = 0; i < RULES_COUNT; i++) {
            rule_t *rule = &FW_RULES[i];
            printk(KERN_INFO "Comparing against:  %s\n", rule->rule_name);
            if (rule->direction != DIRECTION_ANY && rule->direction != direction)
                continue;
            if (rule->src_ip != IP_ANY && (src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask))
                continue;
            if (rule->dst_ip != IP_ANY && (dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask))
                continue;
            if (rule->src_port != PORT_ANY && rule->src_port != src_port)
                continue;
            if (rule->dst_port != PORT_ANY && rule->dst_port != dst_port)
                continue;
            if (rule->protocol != PROT_ANY && rule->protocol != protocol)
                continue;
            if (protocol == PROT_TCP && rule->ack != ACK_ANY && rule->ack != ack)
                continue;

            printk(KERN_INFO "\n**** Matched rule %s ****\n", rule->rule_name);
            // Create and initialize a new log_row_t object
            // Populate the log entry fields
            log_entry.action = rule->action;          // Placeholder: set appropriate action later
            // if(i == RULES_COUNT - 1)
            //     log_entry.reason = REASON_NO_MATCHING_RULE;   
            // else              
            log_entry.reason = i;   
            add_or_update_log_entry(&log_entry);
            print_packet_logs();
            return rule->action; // Return the matching rule's action
        }
    } else{
        log_entry.reason = REASON_XMAS_PACKET;
        log_entry.action = NF_DROP;
        add_or_update_log_entry(&log_entry);
        print_packet_logs();
        return NF_DROP;
    }

    log_entry.action = NF_DROP;
    log_entry.reason = REASON_NO_MATCHING_RULE;   
    return NF_DROP;
}

static unsigned int module_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned int verdict = NF_DROP;
    struct iphdr *ip_header;

    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT; // Accept non-IPv4 packets (e.g., IPv6)
    }

    // Check for loopback packets (127.0.0.1/8)
    if ((ntohl(ip_header->saddr) & 0xFF000000) == 0x7F000000) {
        return NF_ACCEPT; // Accept loopback packets without logging
    }

    // Accept any non-TCP, UDP, or ICMP protocol without logging
    if (ip_header->protocol != PROT_TCP && ip_header->protocol != PROT_UDP && ip_header->protocol != PROT_ICMP) {
        return NF_ACCEPT;
    }

    verdict = comp_packet_to_rules(skb, state);
    return verdict;
}



static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display, modify);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_store);

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = my_read,
};


// Initialization function; handles error registering the hooks with cleanups and an indicative return value
static int __init fw_init(void) {    
    int ret;
    printk(KERN_INFO "Loading hw1secws module...!\n");
    // ******
    // Devices setup
    // ******

    //create char device
	major_number = register_chrdev(0, "fw_log", &fops);
    printk(KERN_INFO "Major number %d\n", major_number);
	if (major_number < 0)
		return -1;
		
	//create sysfs class
	sysfs_class = class_create(THIS_MODULE, "fw");
	if (IS_ERR(sysfs_class))
	{
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	
	//create sysfs device
	sysfs_device = device_create(sysfs_class, NULL, MKDEV(major_number, 0), NULL, "rules");	
	if (IS_ERR(sysfs_device))
	{
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}
	
	//create sysfs file attributes	
	if (device_create_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr))
	{
		device_destroy(sysfs_class, MKDEV(major_number, 0));
		class_destroy(sysfs_class);
		unregister_chrdev(major_number, "fw_log");
		return -1;
	}

    log_device = device_create(sysfs_class, NULL, MKDEV(major_number, 1), NULL, "log");
    if (IS_ERR(log_device))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return -1;
    }

    // Create the "reset" sysfs attribute for the "log" device
    if (device_create_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return -1;
    }

    // ******
    // Netfilter Hooks
    // ******

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

static void __exit fw_exit(void)
{
    printk(KERN_INFO "Removing hw1secws module...\n");
    // ****** Device Cleanup ******
    if (sysfs_device)
    {
        device_remove_file(sysfs_device, (const struct device_attribute *)&dev_attr_rules.attr);
        device_destroy(sysfs_class, MKDEV(major_number, 0));
    }

    // Remove the "reset" sysfs attribute and device if they exist
    if (log_device)
    {
        device_remove_file(log_device, (const struct device_attribute *)&dev_attr_reset.attr);
        device_destroy(sysfs_class, MKDEV(major_number, 1));
    }

    // Destroy the sysfs class (only after all devices are cleaned up)
    if (sysfs_class)
        class_destroy(sysfs_class);

    // Unregister the character device
    unregister_chrdev(major_number, "fw_log");

    // ****** Netfilter Cleanup ******
    nf_unregister_net_hook(&init_net, &netfilter_ops_fw);

    printk(KERN_INFO "hw1secws module removed successfully.\n");
}

module_init(fw_init);
module_exit(fw_exit);