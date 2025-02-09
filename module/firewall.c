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
#include <net/checksum.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/tcp.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Razaq");
MODULE_DESCRIPTION("Stateful Firewall");
MODULE_VERSION("1");

static int major_number;
static struct class* sysfs_class = NULL;
static struct device* sysfs_device = NULL;
struct device *log_device;
struct device *conns_device;
struct device *mitm_device;

// Define packet_log struct
struct packet_log {
    log_row_t log_object;       // The log entry object
    struct klist_node node;     // Node for inclusion in the klist
};

// Define connection_row struct for connections_table
typedef struct{
    connection_rule_t connection_rule_srv;       
    connection_rule_t connection_rule_cli;       
    struct klist_node node;
} connection_rule_row;

// Define the static klist for packet logs
static struct klist packet_logs = KLIST_INIT(packet_logs, NULL, NULL);
static int logs_num = 0;


// Define the static klist for packet logs
static struct klist connections_table = KLIST_INIT(connections_table, NULL, NULL);

// Netfilter hooks for relevant packet phases
static struct nf_hook_ops netfilter_ops_fw;
static struct nf_hook_ops netfilter_ops_fw_local_out;

static int RULES_COUNT = 0;
static rule_t* FW_RULES;

void print_tcp_packet(struct sk_buff *skb) {
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Ensure the skb is valid and contains an IP header
    if (!skb)
        return;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != PROT_TCP) {
        pr_info("Not a TCP packet\n");
        return;
    }

    // Get the TCP header
    tcph = tcp_hdr(skb);
    if (!tcph) {
        pr_info("TCP header is NULL\n");
        return;
    }

    // Print source and destination IP addresses
    pr_info("Source IP: %pI4\n", &iph->saddr);
    pr_info("Destination IP: %pI4\n", &iph->daddr);

    // Print source and destination ports
    pr_info("Source Port: %u\n", ntohs(tcph->source));
    pr_info("Destination Port: %u\n", ntohs(tcph->dest));

    // Print TCP flags
    pr_info("TCP Flags: [");
    if (tcph->fin)
        pr_cont("FIN ");
    if (tcph->syn)
        pr_cont("SYN ");
    if (tcph->rst)
        pr_cont("RST ");
    if (tcph->psh)
        pr_cont("PSH ");
    if (tcph->ack)
        pr_cont("ACK ");
    if (tcph->urg)
        pr_cont("URG ");
    if (tcph->ece)
        pr_cont("ECE ");
    if (tcph->cwr)
        pr_cont("CWR ");
    pr_cont("]\n");
}


void print_tcp_data(const tcp_data_t *data) {
    if (!data) {
        pr_err("[tcp_data_t] Null pointer provided.\n");
        return;
    }

    pr_info("[tcp_data_t]\n");
    pr_info("Source Port: %u\n", ntohs(data->src_port));
    pr_info("Destination Port: %u\n", ntohs(data->dst_port));

    pr_info("ACK: %s\n", (data->ack == ACK_NO) ? "NO" : (data->ack == ACK_YES) ? "YES" : "ANY");
    pr_info("SYN: %s\n", (data->syn == SYN_NO) ? "NO" : (data->syn == SYN_YES) ? "YES" : "ANY");
    pr_info("FIN: %s\n", (data->fin == FIN_NO) ? "NO" : (data->fin == FIN_YES) ? "YES" : "ANY");
    pr_info("RST: %s\n", (data->rst == RST_NO) ? "NO" : (data->rst == RST_YES) ? "YES" : "ANY");
}

static void print_packet_identifier(const packet_identifier_t *pkt)
{
    char src_ip[16];
    char dst_ip[16];

    // Convert the source and destination IPs to human-readable strings
    snprintf(src_ip, sizeof(src_ip), "%pI4", &pkt->src_ip);
    snprintf(dst_ip, sizeof(dst_ip), "%pI4", &pkt->dst_ip);

    // Log the packet identifier details
    printk(KERN_INFO "Packet Identifier:\n");
    printk(KERN_INFO "  Source IP: %s\n", src_ip);
    printk(KERN_INFO "  Destination IP: %s\n", dst_ip);
    printk(KERN_INFO "  Source Port: %u\n", ntohs(pkt->src_port));
    printk(KERN_INFO "  Destination Port: %u\n", ntohs(pkt->dst_port));
}

static direction_t get_direction_incoming(const struct nf_hook_state *state) {
    return strcmp(state->in->name, IN_NET_DEVICE_NAME) == 0 ? DIRECTION_IN : DIRECTION_OUT;
}

static direction_t get_direction_outgoing(const struct nf_hook_state *state) {
    return strcmp(state->out->name, IN_NET_DEVICE_NAME) == 0 ? DIRECTION_OUT : DIRECTION_IN;
}

static int is_active_connection (connection_rule_row* rule){
    return ((rule->connection_rule_cli.state != STATE_CLOSED) || (rule->connection_rule_srv.state != STATE_CLOSED) );
}

static __be32 ip_string_to_be32(const char *ip_string)
{
    __be32 ip_32be = 0; // Initialize to 0 (error indicator)

    if (!ip_string || ip_string[0] == '\0') {
        pr_err("ip_string_to_be32: Invalid input (NULL or empty string).\n");
        return 0; // Return 0 to indicate an error
    }

    if (!in4_pton(ip_string, -1, (u8 *)&ip_32be, '\0', NULL)) {
        pr_err("ip_string_to_be32: Failed to parse IP string: %s\n", ip_string);
        return 0; // Return 0 to indicate an error
    }

    return ip_32be; // Return the converted __be32 value
}

static log_row_t init_log_entry(packet_identifier_t packet_identifier, __u8 protocol) {
	log_row_t log_entry;

	// Initialize the log entry fields
	log_entry.timestamp = jiffies;            // Use jiffies as the timestamp
	log_entry.protocol = protocol;           // Protocol passed to the function
	log_entry.src_ip = packet_identifier.src_ip; // Source IP from the packet identifier
	log_entry.dst_ip = packet_identifier.dst_ip; // Destination IP from the packet identifier
	log_entry.src_port = packet_identifier.src_port; // Source port
	log_entry.dst_port = packet_identifier.dst_port; // Destination port
	log_entry.action = 0;                    // Default action (can be updated later)
	log_entry.reason = 0;                    // Default reason (can be updated later)
	log_entry.count = 1;                     // Initialize count to 1
    log_entry.ignore = 0;

	return log_entry;
}


int compare_packets(packet_identifier_t p1, packet_identifier_t p2){
    return (p1.src_ip == p2.src_ip && 
    p1.dst_ip == p2.dst_ip && 
    p1.src_port == p2.src_port && 
    p1.src_port == p2.src_port && 
    p1.dst_port == p2.dst_port && 
    p1.src_port == p2.src_port);
}

// Display_rules the rules
ssize_t display_rules(struct device *dev, struct device_attribute *attr, char *buf) 
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
                         rule->protocol,
                         rule->src_port,
                         rule->dst_port,
                         rule->ack,
                         rule->action);
        // Check if the buffer is full
        if (len >= PAGE_SIZE)
            break;
    }

    return len;
}


int convert_src_port(const char *src_port_str, __be16 *network_port) {
    int src_port;
    int ret;

    // Convert string to integer
    ret = kstrtoint(src_port_str, 10, &src_port);
    if (ret) {
        printk(KERN_ERR "Invalid src_port string: %s\n", src_port_str);
        return -EINVAL;  // Invalid argument
    }

    // Check for valid port range (1-65535)
    if (src_port < 1 || src_port > 65535) {
        printk(KERN_ERR "Port out of range: %d\n", src_port);
        return -ERANGE;
    }

    // Convert to network byte order
    *network_port = htons((uint16_t)src_port);

    return 0;
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
    return rows + 1;
}


static int parse_rule(const char *rule_str, rule_t *rule) {
    char src_ip_prefix[32], dst_ip_prefix[32], src_port_str[10], dst_port_str[10];
    char direction_str[10], protocol_str[10], ack_str[10], action_str[10];
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
        if (convert_src_port(src_port_str, &rule->src_port) != 0){
            printk(KERN_CRIT "Error in provided rule port: %s", src_port_str);
            return -EINVAL;
        }
    }

    if (strcmp(dst_port_str, "any") == 0) {
        rule->dst_port = PORT_ANY;
    } else if (strcmp(dst_port_str, ">1023") == 0){
        rule->dst_port = PORT_ABOVE_1023;
    } else {
        if (convert_src_port(dst_port_str, &rule->dst_port) != 0){
            printk(KERN_CRIT "Error in provided rule port: %s", dst_port_str);
            return -EINVAL;
        }
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



// Modify_rules the rules 
ssize_t modify_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    char *rules_str, *tmp_rules_str, *line;
    int i = 0;
    int num_of_rules = get_rules_number(buf, count);
    static DEFINE_MUTEX(rules_mutex);

    // Allocate FW_RULES
    FW_RULES = kmalloc_array(num_of_rules, sizeof(rule_t), GFP_KERNEL);
    if (!FW_RULES) {
        printk(KERN_ALERT "Memory allocation failed for FW_RULES.\n");
        return -ENOMEM;
    }

    // Allocate memory for rules_str
    rules_str = kmalloc(count + 1, GFP_KERNEL);
    if (!rules_str) {
        kfree(FW_RULES);  // Free FW_RULES if rules_str allocation fails
        return -ENOMEM;
    }

    strncpy(rules_str, buf, count);
    rules_str[count] = '\0';
    tmp_rules_str = rules_str;

    mutex_lock(&rules_mutex);  // Protect critical section

    for (line = strsep(&tmp_rules_str, "\n"); line != NULL; line = strsep(&tmp_rules_str, "\n")) {
        if (i > num_of_rules) {
            printk(KERN_ALERT "Rule count exceeded allocated space.\n");
            break;
        }
        if (*line == '\0') continue;
        if (parse_rule(line, &FW_RULES[i]) < 0) {
            printk(KERN_ALERT "ERROR IN Rule Parsing.");
            printk(KERN_ALERT "Terminating ...");
            kfree(FW_RULES);
            RULES_COUNT = 0;
            kfree(rules_str);
            mutex_unlock(&rules_mutex);
            return -EINVAL;
        }
        i++;
    }

    RULES_COUNT = i;

    kfree(rules_str);
    mutex_unlock(&rules_mutex);

    return count;
}

// Reset the logs
ssize_t reset_logs(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
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


// Read the logs
ssize_t read_logs(struct file *filp, char __user *user_buf, size_t count, loff_t *f_pos)
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
                           log->src_port, log->dst_port,
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

void print_connection(  connection_rule_row *entry){
            printk(KERN_INFO
               "Src_IP=%pI4, Dst_IP=%pI4, Src_Port=%u, Dst_Port=%u, MITM_Proc_port=%u "
               "State=%u",
               &entry->connection_rule_srv.packet.src_ip,
               &entry->connection_rule_srv.packet.dst_ip,
               ntohs(entry->connection_rule_srv.packet.src_port),
               ntohs(entry->connection_rule_srv.packet.dst_port),
               ntohs(entry->connection_rule_srv.mitm_proc_port),
               entry->connection_rule_srv.state);
            printk(KERN_INFO
               "Src_IP=%pI4, Dst_IP=%pI4, Src_Port=%u, Dst_Port=%u, MITM_Proc_port=%u"
               "State=%u",
               &entry->connection_rule_cli.packet.src_ip,
               &entry->connection_rule_cli.packet.dst_ip,
               ntohs(entry->connection_rule_cli.packet.src_port),
               ntohs(entry->connection_rule_cli.packet.dst_port),
               ntohs(entry->connection_rule_cli.mitm_proc_port),
               entry->connection_rule_cli.state);
}

void print_connections_table(void) {
    struct klist_iter iter;
    struct klist_node *knode;
     connection_rule_row *entry;

    printk(KERN_INFO "=== Printing Connecitnos Table Logs ===\n");

    // Initialize the iterator for the klist
    klist_iter_init(&connections_table, &iter);

    // Iterate over the klist
    while ((knode = klist_next(&iter))) {
        entry = container_of(knode,  connection_rule_row, node);
        print_connection(entry);
    }

    // Exit the iterator
    klist_iter_exit(&iter);

    printk(KERN_INFO "=== End of Connectinos Table ===\n");
}


static ssize_t read_connections_table(struct device *dev, struct device_attribute *attr, char *buf) {
    struct klist_iter iter;
    struct klist_node *knode;
     connection_rule_row *entry;
    size_t offset = 0;
    char temp_buffer[128];
    ssize_t len;

    klist_iter_init(&connections_table, &iter);

    while ((knode = klist_next(&iter)) != NULL) {
        entry = container_of(knode,  connection_rule_row, node);
        len = snprintf(temp_buffer, sizeof(temp_buffer),
                       "%pI4,%u,%pI4,%u,%u,%u\n",
                       &entry->connection_rule_srv.packet.src_ip,
                       ntohs(entry->connection_rule_srv.packet.src_port),
                       &entry->connection_rule_srv.packet.dst_ip,
                       ntohs(entry->connection_rule_srv.packet.dst_port),
                       ntohs(entry->connection_rule_srv.mitm_proc_port),
                       entry->connection_rule_srv.state);

        if (len < 0 || offset + len >= PAGE_SIZE) {
            break;
        }

        memcpy(buf + offset, temp_buffer, len);
        offset += len;

        len = snprintf(temp_buffer, sizeof(temp_buffer),
                       "%pI4,%u,%pI4,%u,%u,%u\n",
                       &entry->connection_rule_cli.packet.src_ip,
                       ntohs(entry->connection_rule_cli.packet.src_port),
                       &entry->connection_rule_cli.packet.dst_ip,
                       ntohs(entry->connection_rule_cli.packet.dst_port),
                       ntohs(entry->connection_rule_cli.mitm_proc_port),
                       entry->connection_rule_cli.state);

        if (len < 0 || offset + len >= PAGE_SIZE) {
            break;
        }

        memcpy(buf + offset, temp_buffer, len);
        offset += len;
    }

    klist_iter_exit(&iter);

    return offset;
}




void add_or_update_log_entry(log_row_t *new_entry) {
    struct klist_iter iter;
    struct klist_node *knode;
    struct packet_log *existing_entry;
    int found = 0;

    if (new_entry->ignore) return;

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
            existing_entry->log_object.protocol == new_entry->protocol && 
            existing_entry->log_object.action == new_entry->action) {
            
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

static tcp_data_t* get_tcp_data(struct sk_buff *skb) {
    struct tcphdr *tcph;
    tcp_data_t* tcp_data;

    // Allocate memory for tcp_data
    tcp_data = kmalloc(sizeof(tcp_data_t), GFP_KERNEL);
    if (!tcp_data) {
        printk(KERN_ERR "@get_tcp_data Memory allocation failed\n");
        return NULL;
    }

    tcph = tcp_hdr(skb);
    if (!tcph){
        printk(KERN_ERR "@get_tcp_data Could not read TCP Header ");
        return NULL;
    }
    tcp_data->src_port = (tcph->source);
    tcp_data->dst_port = (tcph->dest);
    tcp_data->ack = (tcph->ack ? ACK_YES : ACK_NO);
    tcp_data->syn = (tcph->syn ? SYN_YES : SYN_NO);
    tcp_data->fin = (tcph->fin ? FIN_YES : FIN_NO);
    tcp_data->rst = (tcph->rst ? RST_YES : RST_NO);
    return tcp_data;
}


static  connection_rule_row *find_connection_row_by_proxy(packet_identifier_t* packet_identifier_local_out, __be16 mitm_proc_port, direction_t dir) {
    struct klist_iter iter;
    struct klist_node *knode;
    connection_rule_row *row;
    connection_rule_row *original_row = NULL;

    klist_iter_init(&connections_table, &iter);

    // Iterate over the klist to find a matching entry
    while ((knode = klist_next(&iter))) {
        row = container_of(knode,  connection_rule_row, node);
        if (dir == DIRECTION_IN){
            if (row->connection_rule_srv.mitm_proc_port == mitm_proc_port ||
                row->connection_rule_cli.mitm_proc_port == mitm_proc_port) {
                klist_iter_exit(&iter);
                original_row = row; 
                break;
            }
        } else if (dir == DIRECTION_OUT) {
            if (row->connection_rule_cli.packet.src_ip == packet_identifier_local_out->dst_ip &&
                row->connection_rule_cli.packet.src_port == packet_identifier_local_out->dst_port) {
                original_row = row;
                break;
            }
        }
    }

    klist_iter_exit(&iter);
    if (!original_row) {
        printk(KERN_ERR "Original packet not found");
        print_connections_table();
        print_packet_identifier(packet_identifier_local_out);
    }
    return original_row; // No match found
}

static void extract_transport_fields(struct sk_buff *skb, __u8 protocol, __be16 *src_port,
                                    __be16 *dst_port, __u8 *syn, __u8 *ack, __u8 *fin, __u8 *rst,
                                    int* is_christmas_packet) { 
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
            *src_port = (tcp_header->source);
            *dst_port = (tcp_header->dest);
            *ack = (tcp_header->ack ? ACK_YES : ACK_NO);
            *syn = (tcp_header->syn ? SYN_YES : SYN_NO);
            *fin = (tcp_header->fin ? FIN_YES : FIN_NO);
            *rst = (tcp_header->rst ? RST_YES : RST_NO);

            // Check if the packet is a Christmas tree packet
            if (tcp_header->fin && tcp_header->urg && tcp_header->psh) {
                *is_christmas_packet = 1; // Mark as true
            }
        }
    } else if (protocol == PROT_UDP) {
        udp_header = udp_hdr(skb);
        if (udp_header) {
            *src_port = (udp_header->source);
            *dst_port = (udp_header->dest);
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

static  connection_rule_row* find_connection_row(packet_identifier_t packet_identifier){
    struct klist_iter iter;
    struct klist_node *knode;
     connection_rule_row *existing_entry;
    int counter = 0;

    // Initialize an iterator for the klist
    klist_iter_init(&connections_table, &iter);

    // Iterate over the klist to find a matching entry
    while ((knode = klist_next(&iter))) {
        existing_entry = container_of(knode,  connection_rule_row, node);
        if (compare_packets(existing_entry->connection_rule_cli.packet, packet_identifier) ||
            compare_packets(existing_entry->connection_rule_srv.packet, packet_identifier)){
            return existing_entry;
        }
        counter++;
    }

    // Exit the iterator
    klist_iter_exit(&iter);
    return NULL;
}


static void reverse_packet_identifier(const packet_identifier_t *packet, packet_identifier_t *reversed) {
    reversed->src_ip = packet->dst_ip;
    reversed->dst_ip = packet->src_ip;
    reversed->src_port = packet->dst_port;
    reversed->dst_port = packet->src_port;
}

static int handle_restart_existing_connection(connection_rule_row* found_connection, packet_identifier_t packet_identifier) {
    int sender_client;
    if (is_active_connection(found_connection)) {
        printk(KERN_ERR "initiate_connection Error: Connection already exists.");
        return NF_DROP;
    } else {
        printk(KERN_ERR "initiate_connection: Restarting existing connection");
        sender_client = compare_packets(packet_identifier, found_connection->connection_rule_cli.packet);
        found_connection->connection_rule_cli.state = sender_client ? STATE_SYN_SENT: STATE_LISTEN;
        found_connection->connection_rule_srv.state = sender_client ? STATE_LISTEN: STATE_SYN_SENT;
        return NF_ACCEPT;
    }   
}

static int initiate_connection(packet_identifier_t packet_identifier) {
        connection_rule_row* found_connection = find_connection_row(packet_identifier);
        packet_identifier_t *reversed_packet_identifier;
        connection_rule_row *new_rule_sender;
        if (found_connection != NULL)
            return handle_restart_existing_connection(found_connection, packet_identifier);

        // Allocate memory for reversed_packet_identifier
        reversed_packet_identifier = kmalloc(sizeof(packet_identifier_t), GFP_KERNEL);
        if (!reversed_packet_identifier) {
            printk(KERN_ERR "Memory allocation failed for reversed_packet_identifier\n");
            return NF_DROP;
        }
        reverse_packet_identifier(&packet_identifier, reversed_packet_identifier);

        // Allocate memory for new_rule_sender and new_rule_reciever
        new_rule_sender = kmalloc(sizeof( connection_rule_row), GFP_KERNEL);
        if (!new_rule_sender) {
            printk(KERN_ERR "Memory allocation failed for new_rule_sender\n");
            kfree(reversed_packet_identifier);
            return NF_DROP;
        }

        // Initialize the state rules
        new_rule_sender->connection_rule_cli.state = STATE_SYN_SENT;
        new_rule_sender->connection_rule_srv.state = STATE_LISTEN;

        // Copy packet identifiers
        memcpy(&new_rule_sender->connection_rule_cli.packet, &packet_identifier, sizeof(packet_identifier_t));
        memcpy(&new_rule_sender->connection_rule_srv.packet, reversed_packet_identifier, sizeof(packet_identifier_t));

        // Free reversed_packet_identifier after use
        kfree(reversed_packet_identifier);

        klist_add_tail(&new_rule_sender->node, &connections_table);

    print_connections_table();
    return NF_ACCEPT;
}


static int comp_packet_to_static_rules(packet_identifier_t packet_identifier, __u8 protocol, __u8 ack, direction_t direction) {
    int i;
    for (i = 0; i < RULES_COUNT; i++) {
        rule_t *rule = &FW_RULES[i];
        // printk(KERN_CRIT "Comparing against %s", rule->rule_name);
        if (rule->direction != DIRECTION_ANY && rule->direction != direction){
            // printk(KERN_CRIT "Dropped at direction");
            continue;
        }
        if (rule->src_ip != IP_ANY && (packet_identifier.src_ip & rule->src_prefix_mask) != (rule->src_ip & rule->src_prefix_mask)){
            // printk(KERN_CRIT "Dropped at src_ip");
            continue;
        }
        if (rule->dst_ip != IP_ANY && (packet_identifier.dst_ip & rule->dst_prefix_mask) != (rule->dst_ip & rule->dst_prefix_mask)){
            // printk(KERN_CRIT "Dropped at dst_ip");
            continue;
        }
        if (rule->src_port != PORT_ANY && rule->src_port != packet_identifier.src_port){
            if (rule->src_port != PORT_ABOVE_1023){
                // printk(KERN_CRIT "Dropped at port src_port != PORT_ABOVE_1023");
                continue;
            }
            if (packet_identifier.src_port < 1023){
                // printk(KERN_CRIT "Dropped at port src_port < 1023");
                continue;
            }
        }
        if (rule->dst_port != PORT_ANY && rule->dst_port != packet_identifier.dst_port){
            if (rule->dst_port != PORT_ABOVE_1023){
                // printk(KERN_CRIT "Dropped at dst_port  != PORT_ABOVE_1023");
                continue;
            }
            if (packet_identifier.dst_port < 1023){
                // printk(KERN_CRIT "Dropped at dst_port  <1023");
                continue;
            }
        }
        if (rule->protocol != PROT_ANY && rule->protocol != protocol){
            // printk(KERN_CRIT "Dropped at protocol");
            continue;
        }
        if (protocol == PROT_TCP && rule->ack != ACK_ANY && rule->ack != ack){
            // printk(KERN_CRIT "Dropped at ack");
            continue;
        }
        return i;
    }
    return -1;
} 


static ssize_t modify_mitm_port(struct device *dev, struct device_attribute *attr, const char *buf, size_t count) {
    char input[64]; // Buffer for user input
    char *token, *cur;
    struct klist_iter iter;
    struct klist_node *knode;
     connection_rule_row *row;
    int i = 0;
    packet_identifier_t packet_identifier;

    char cli_ip[16], srv_ip[16]; // Buffers for IP addresses
    int cli_port, srv_port, mitm_port;     // Variables for ports
    int ret;
    __be32 src_ip;

    // Check if the input starts with '#'
    if (buf[0] == '#') {
        printk(KERN_INFO "\n\n -- PORT COMMAND --\n");
        // Parse the input string according to the given format
        ret = sscanf(buf, "#%15[^,],%d,%15[^,],%d\n", cli_ip, &cli_port, srv_ip, &srv_port);
        if (ret != 4) { // Ensure all four values are parsed successfully
            pr_err("Invalid input format. Expected format: \"#{},{},{},{}\\n\"\n");
            return -EINVAL; // Return error if parsing fails
        }
        packet_identifier.dst_ip = ip_string_to_be32(cli_ip);
        packet_identifier.src_ip = ip_string_to_be32(srv_ip);
        packet_identifier.dst_port = htons(cli_port);
        packet_identifier.src_port = htons(srv_port);
        if(!initiate_connection(packet_identifier)){
                printk(KERN_ERR "Connection could not be intiated");
                return -EINVAL;
        } 
        print_packet_identifier(&packet_identifier);
        return count; // Indicate success
    }


    // Copy input for parsing
    if (count >= sizeof(input)) {
        pr_err("Input too long\n");
        return -EINVAL;
    }
    strncpy(input, buf, count);
    input[count] = '\0';

    // Parse user input
    cur = input;
    while ((token = strsep(&cur, ",")) != NULL) {
        if (i == 0)
            src_ip = ip_string_to_be32(token); // Convert IP string to __be32
        else if (i == 1)
            cli_port = htons(simple_strtoul(token, NULL, 10)); // Convert to __be16
        else if (i == 2)
            mitm_port = htons(simple_strtoul(token, NULL, 10)); // Convert to __be16
        else
            break;
        i++;
    }

    if (i != 3) {
        pr_err("Invalid input format. Expected: <src_ip>,<src_port>,<mitm_port>\n");
        return -EINVAL;
    }

    // Search for the matching rule in the connection table
    klist_iter_init(&connections_table, &iter);

    while ((knode = klist_next(&iter))) {
        row = container_of(knode,  connection_rule_row, node);
        if (row->connection_rule_cli.packet.src_ip == src_ip &&
            row->connection_rule_cli.packet.src_port == cli_port) {
            // Update the MITM port in the connection_rule_srv.packet
            row->connection_rule_srv.mitm_proc_port = mitm_port;
            pr_info("MITM port updated successfully: %pI4:%d -> %d\n",
                    &src_ip, ntohs(cli_port), ntohs(mitm_port));
            klist_iter_exit(&iter);
            return count; // Indicate success
        }
    }

    klist_iter_exit(&iter);
    printk(KERN_ERR "No matching connection rule found for: %pI4:%d\n", &src_ip, ntohs(srv_ip));
    return -ENOENT; // No entry found
}



static int handle_fin_state( connection_rule_row* connection, connection_rule_t* rule, 
                            int sender, int rule_owner, connection_rule_t* other_rule, __u8 ack, __u8 fin){
    int packet_sent = (sender == rule_owner);
    char* terminator = (sender == 0) ? "srv": "cli";
        switch (rule->state) {
            case STATE_ESTABLISHED:
                if (fin == FIN_YES && (packet_sent)) {
                    printk(KERN_INFO "%s terminating the session", terminator);
                    rule->state = STATE_FIN_WAIT_1;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                if (fin == FIN_NO && packet_sent )
                {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Established -> Close_Wait", terminator);
                    rule->state = STATE_CLOSE_WAIT;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;
            case STATE_FIN_WAIT_1:
                if (packet_sent) { // Handle simultanuous closing.....
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_1 -> Closing", terminator);
                    rule->state = STATE_CLOSING;
                    other_rule->state = STATE_CLOSED;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                else if (fin == FIN_NO && !packet_sent  && (other_rule->state <= STATE_LAST_ACK)) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_1 -> Wait_2", terminator);
                    rule->state = STATE_FIN_WAIT_2;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                else if (fin == FIN_NO && !packet_sent  && (other_rule->state > STATE_LAST_ACK)) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_1 -> CLOSED", terminator);
                    rule->state = STATE_CLOSED;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;

            case STATE_FIN_WAIT_2:
                if (packet_sent) { // Received fin and responded with ack.
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_2 -> CLOSED", terminator);
                    rule->state = STATE_CLOSED;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;

            case STATE_CLOSING:
                if (!packet_sent) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Closing -> CLOSED", terminator);
                    rule->state = STATE_CLOSED;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;
            case STATE_CLOSE_WAIT:
                if (fin == FIN_YES && packet_sent) { // Received fin and responded with ack.
                        printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Close_wait -> Last_ACK", terminator);
                        rule->state = STATE_LAST_ACK;
                        print_connections_table();
                        return NF_ACCEPT;
                    }
                    break;
            case STATE_LAST_ACK:
                if (!packet_sent) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Last_ACK -> Closed", terminator);
                        rule->state = STATE_CLOSED;
                        print_connections_table();
                        return NF_ACCEPT;
                    }
                    break;

            default:
                printk(KERN_INFO "\n\n*** STATCE_MACHINE_%s: Dropping by default *** \n\n", terminator);
                return NF_DROP;
        }
        return NF_DROP;
        
}

// Handles TCP state machine and changes the state accordingly. 
// Returns verdict NF_ACCEPT (allow packet) or NF_DROP (drop packet)
static int handle_tcp_state_machine(packet_identifier_t packet_identifier, 
                                     connection_rule_row* found_connection, 
                                    __u8 syn, __u8 ack, __u8 rst, __u8 fin) {
    connection_rule_t* srv_rule = &found_connection->connection_rule_srv;
    connection_rule_t* cli_rule = &found_connection->connection_rule_cli;
    int sender_client = compare_packets(packet_identifier, cli_rule->packet);
    int srv_verdict, cli_verdict;
    printk(KERN_INFO "\n\n Inside TCP State Machin \n\n");
    print_connection(found_connection);
    printk (KERN_INFO "TCP Packet flags:\n SYN = %d   ACK = %d   RST = %d   FIN = %d", syn, ack, rst, fin);
    // Handle RST (Reset): Always drop connection on RST
    if (rst == RST_YES) {
        srv_rule->state = STATE_CLOSED;
        cli_rule->state = STATE_CLOSED;
        printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for rst = 1");
        print_connections_table();
        return NF_ACCEPT;
    }

    // Handle server-side state transitions
    switch (srv_rule->state) {
        case STATE_LISTEN:
            if (syn == SYN_YES && ack == ACK_YES && !sender_client) {
                printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for Listen -> Syn_received");
                srv_rule->state = STATE_SYN_RECEIVED;
                print_connections_table();
                srv_verdict = NF_ACCEPT;
            }
            break;
        case STATE_SYN_SENT:
            if ((cli_rule->state == STATE_SYN_RECEIVED || cli_rule->state == STATE_ESTABLISHED) && 
                !sender_client && syn == SYN_NO && ack == ACK_YES) {
                    printk(KERN_INFO "STATCE_MACHINE_cli: Accepting for STATE_SYN_SENT -> Established");
                print_connections_table();
                srv_rule->state = STATE_ESTABLISHED;
                srv_verdict = NF_ACCEPT;
            }
            break;

        case STATE_SYN_RECEIVED:
            if (ack == ACK_YES && syn == SYN_NO && sender_client) {
                printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for Syn_received -> Established");
                srv_rule->state = STATE_ESTABLISHED;
                print_connections_table();
                srv_verdict = NF_ACCEPT;
            }
            break;
        case STATE_ESTABLISHED:
            if (ack == ACK_YES && fin == FIN_NO && cli_rule->state == STATE_ESTABLISHED){
                printk(KERN_INFO "STATCE_MACHINE_srv: accepting data packet");
                srv_verdict = NF_ACCEPT;
                break;
            }
        default:
            srv_verdict = handle_fin_state(found_connection, srv_rule, sender_client, 0, cli_rule, ack, fin);
    }

    // Handle client-side state transitions
    switch (cli_rule->state) {
        case STATE_LISTEN:
            if (syn == SYN_YES && ack == ACK_YES && sender_client) {
                printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for Listen -> Syn_received");
                cli_rule->state = STATE_SYN_RECEIVED;
                print_connections_table();
                cli_verdict = NF_ACCEPT;
            }
            break;
        case STATE_SYN_RECEIVED:
            if (ack == ACK_YES && syn == SYN_NO && !sender_client) {
                printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for Syn_received -> Established");
                cli_rule->state = STATE_ESTABLISHED;
                print_connections_table();
                cli_verdict = NF_ACCEPT;
            }
            break;
        case STATE_SYN_SENT:
            if ((srv_rule->state == STATE_SYN_RECEIVED || srv_rule->state == STATE_ESTABLISHED) && 
                sender_client && syn == SYN_NO && ack == ACK_YES) {
                    printk(KERN_INFO "STATCE_MACHINE_cli: Accepting for STATE_SYN_SENT -> Established");
                print_connections_table();
                cli_rule->state = STATE_ESTABLISHED;
                cli_verdict = NF_ACCEPT;
            }
            break;
        case STATE_ESTABLISHED:
            if (ack == ACK_YES && fin == FIN_NO && srv_rule->state == STATE_ESTABLISHED){
                printk(KERN_INFO "STATCE_MACHINE_cli: accepting data packet");
                srv_verdict = NF_ACCEPT;
                break;
            }
        default:
            cli_verdict = handle_fin_state(found_connection, cli_rule, sender_client, 1, srv_rule, ack, fin);
    }

    return (srv_verdict == NF_ACCEPT || cli_verdict == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
}


static void tcp_handle_syn(packet_identifier_t packet_identifier, log_row_t* pt_log_entry, int *pt_verdict,
                           __u8 syn, direction_t direction) {
    int found_rule_index;
    printk(KERN_INFO "TCP packet with ack = 0");
    if(direction == DIRECTION_OUT) {
        printk(KERN_ERR "\n\nSuspicious outbound syn - DROPPING\n\n");
        pt_log_entry->action =NF_DROP;
        pt_log_entry->reason = REASON_INVALID_CONNECTION;
        *pt_verdict = NF_DROP;
        return;
    }

    found_rule_index = comp_packet_to_static_rules(packet_identifier, PROT_TCP, ACK_NO, direction);
    if (found_rule_index >= 0) {
        pt_log_entry->action = FW_RULES[found_rule_index].action;      
        pt_log_entry->reason = found_rule_index;   
        *pt_verdict = FW_RULES[found_rule_index].action;
    } else {
        pt_log_entry->action = NF_DROP;
        pt_log_entry->reason = REASON_NO_MATCHING_RULE;   
        printk(KERN_INFO "\nDropping - No static match");
        *pt_verdict = NF_DROP;
    }
}

static void tcp_handle_ack(packet_identifier_t packet_identifier, log_row_t* pt_log_entry, int *pt_verdict,
                            __u8 syn, __u8 ack, __u8 rst, __u8 fin) {
    connection_rule_row* found_connection;
    if(packet_identifier.src_port == HTTP_PORT || packet_identifier.src_port == FTP_PORT || packet_identifier.src_port == SMTP_PORT )
        found_connection = find_connection_row_by_proxy(NULL, packet_identifier.dst_port, DIRECTION_IN);
    else 
        found_connection = find_connection_row(packet_identifier);
    printk(KERN_INFO "**Handling a dynamic packet..");
    // TESTING with the || (srv->cli syn packet) !!!! modify it by checking the LOCAL_PROC_PORT
    if (found_connection == NULL){
        printk (KERN_INFO "\n\nNo connecition found in the table. DROPPING.\n\n");
        pt_log_entry->action = NF_DROP;
        pt_log_entry->reason = REASON_NO_CONNECTION;   
        *pt_verdict = NF_DROP;
    } else {
        printk (KERN_INFO "Connection found. Comparing agains TCP state machine.\n");
        // Syn packet for Active FTP conenction
        if (syn == SYN_YES && ack == ACK_NO){
            *pt_verdict = NF_ACCEPT;
        } else {
            *pt_verdict = handle_tcp_state_machine(packet_identifier, found_connection, syn, ACK_YES, rst, fin);
         }
        if (*pt_verdict)
            pt_log_entry->reason = REASON_VALID_CONNECTION;   
        else
            pt_log_entry->reason = REASON_INVALID_TCP_STATE;   
        pt_log_entry->action = *pt_verdict;
    }
}

static void handle_new_connection(packet_identifier_t packet_identifier, log_row_t* pt_log_entry, 
                                 int *pt_verdict) {
            printk(KERN_INFO "Initiating a new connection");
            // Create a new connection
            if(!initiate_connection(packet_identifier)){
                printk(KERN_ERR "Connection could not be intiated");
                pt_log_entry->action = NF_DROP;
                pt_log_entry->reason = REASON_ILLEGAL_VALUE;
                *pt_verdict = NF_DROP;
            } 
}

static int modify_packet(struct sk_buff *skb, __be32 saddr, __be16 sport, __be32 daddr, __be16 dport){
    struct iphdr *iph;
    struct tcphdr *tcph;
    int tcplen;

    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    if (daddr)
        iph->daddr = daddr;
    if (dport)
        tcph->dest = dport;
    if (saddr)
        iph->saddr = saddr;
    if (sport)
        tcph->source = sport;

    /* Fix IP header checksum */
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
    skb->ip_summed = CHECKSUM_NONE;
    skb->csum_valid = 0;

    /* Linearize the skb */
    if (skb_linearize(skb) < 0) {
        return -1;
    }

    /* Re-take headers. The linearize may change skb's pointers */
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    /* Fix TCP header checksum */
    tcplen = (ntohs(iph->tot_len) - ((iph->ihl) << 2));
    tcph->check = 0;
    tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcplen, 0));
    return 0;
}


static int handle_mitm_pre_routing(struct sk_buff *skb, packet_identifier_t packet_identifier, 
                                   const struct nf_hook_state *state, app_prot_t app_prot) {
    __be32 local_ip;
    __be16 local_port; 
    if (app_prot == PROT_HTTP) local_port = LOC_HTTP_PORT; 
    if (app_prot == PROT_FTP) local_port = LOC_FTP_PORT; 
    if (app_prot == PROT_SMTP) local_port = LOC_SMTP_PORT; 

    direction_t dir = get_direction_incoming(state);
    int ret = 0;
    // •	Client-to-server, inbound, pre-routing
    if (dir == DIRECTION_IN){
        local_ip = (in_aton(FW_IN_IP));
        ret = modify_packet(skb, 0, 0, local_ip, local_port);
    } 
    // •	Server-to-client, inbound, pre-routing
    else { 
        local_ip = (in_aton(FW_OUT_IP));
        ret = modify_packet(skb, 0, 0, local_ip, 0);
    }
    printk(KERN_CRIT "MITM - Modifed CLI --> LOCAL:%d\n", ntohs(local_port));
    print_tcp_packet(skb);
    return ret;
}

static int handle_mitm_local_out(struct sk_buff *skb, packet_identifier_t* packet_identifier,
                                tcp_data_t* tcp_data, direction_t dir) {
    __be32 original_ip;
    __be16 original_port;
    __be16 mimt_proc_port;
    connection_rule_row* conn;
    packet_identifier_t original_packet_identifier;
    log_row_t log_entry;
    int ret = 0;

    mimt_proc_port = tcp_data->src_port;
    conn = find_connection_row_by_proxy(packet_identifier, mimt_proc_port, dir);
    if (!conn){
        printk(KERN_ERR "\nError @ Local_out -> Client: Could not find connection by MITM_PORT\n");
        return -1;
    }

    printk(KERN_INFO "Modifying packet @ local_out");
    
    // •	cli-to-server, outbound, local-out,
    if (dir == DIRECTION_IN){
        original_packet_identifier = conn->connection_rule_cli.packet;
        original_ip = (original_packet_identifier.src_ip); // Client's IP
        ret = modify_packet(skb, original_ip, 0, 0, 0);
    } 
    // •	Server-to-client, outbound, local-out,
    else { 
        original_packet_identifier = conn->connection_rule_srv.packet;
        original_port = original_packet_identifier.src_port; // Server's port
        original_ip = (original_packet_identifier.src_ip); // Server's IP
        ret = modify_packet(skb, original_ip, original_port, 0, 0);
        handle_tcp_state_machine(original_packet_identifier, conn, tcp_data->syn, tcp_data->ack, tcp_data->rst, tcp_data->fin);
    }
    if (dir == DIRECTION_OUT && ret >= 0){
        log_entry = init_log_entry(original_packet_identifier, PROT_TCP);
        log_entry.action = NF_ACCEPT;
        log_entry.reason = REASON_VALID_CONNECTION;
        add_or_update_log_entry(&log_entry);
    }
    return ret;
}



static void handle_tcp_pre_routing(struct sk_buff *skb, const struct nf_hook_state *state, 
                       packet_identifier_t packet_identifier, log_row_t* pt_log_entry, int *pt_verdict,
                        __u8 syn, __u8 ack, __u8 rst, __u8 fin, direction_t direction) {
    int ret = 0;
    if (syn == SYN_YES && ack == ACK_NO){
        if(direction == DIRECTION_OUT && packet_identifier.src_port == CONN_FTP_PORT)
            tcp_handle_ack(packet_identifier, pt_log_entry, pt_verdict, syn, ack, rst, fin);
        else {
            tcp_handle_syn(packet_identifier, pt_log_entry, pt_verdict, ack, direction);
            if (*pt_verdict)
                handle_new_connection(packet_identifier, pt_log_entry, pt_verdict);
        }
        
    } else 
        tcp_handle_ack(packet_identifier, pt_log_entry, pt_verdict, syn, ack, rst, fin);
    

    // Proxy stuff 

    if(*pt_verdict && ((packet_identifier.dst_port == (HTTP_PORT) || 
                      (packet_identifier.src_port == (HTTP_PORT) )))){
        printk(KERN_INFO "Handling an HTTP Packet ...");
        ret = handle_mitm_pre_routing(skb, packet_identifier, state, PROT_HTTP);
        if (direction == DIRECTION_OUT) pt_log_entry->ignore = 1;
    } else if(*pt_verdict &&( (packet_identifier.dst_port == (FTP_PORT)) || 
                      (packet_identifier.src_port == (FTP_PORT) )) ){
        printk(KERN_INFO "Handling an FTP Packet ...");
        ret = handle_mitm_pre_routing(skb, packet_identifier, state, PROT_FTP);
        if (direction == DIRECTION_OUT) pt_log_entry->ignore = 1;
    } else if(*pt_verdict && ((packet_identifier.dst_port == SMTP_PORT) || 
                       (packet_identifier.src_port == SMTP_PORT) )){
        printk(KERN_INFO "Handling an SMTP Packet ...");
        ret = handle_mitm_pre_routing(skb, packet_identifier, state, PROT_SMTP);
        if (direction == DIRECTION_OUT) pt_log_entry->ignore = 1;
    }

    if(ret < 0) {
        printk(KERN_ERR "__ CHECKSUM ERROR. DROPPING __");
        *pt_verdict = NF_DROP;
        pt_log_entry->action = NF_DROP;
        pt_log_entry->reason = REASON_MITM_ERR;
    }
}

static void hanlde_non_tcp_pre_routing(packet_identifier_t packet_identifier, log_row_t* log_entry, int *verdict,
                           __u8 protocol, __u8 direction) {
        int found_rule_index = comp_packet_to_static_rules(packet_identifier, protocol, ACK_NO, direction);
        if (found_rule_index >= 0) {
            log_entry->action = FW_RULES[found_rule_index].action;      
            log_entry->reason = found_rule_index;   
            *verdict = FW_RULES[found_rule_index].action;
        } else {
            log_entry->action = NF_DROP;
            log_entry->reason = REASON_NO_MATCHING_RULE;   
            printk(KERN_INFO "\nDropping - No static match");
            *verdict = NF_DROP;
        }
}

// Given a TCP/UDP/ICMP packet
static int get_packet_verdict_pre_routing(struct sk_buff *skb, const struct nf_hook_state *state) {
    packet_identifier_t packet_identifier;
    log_row_t log_entry;
    __u8 ack, syn, fin, rst;
    struct iphdr *ip_header;
    direction_t direction;
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    int is_christmas_packet = 0;
    int verdict = NF_DROP;

    memset(&log_entry, 0, sizeof(log_row_t)); // Initialize to zero
    direction = get_direction_incoming(state);

    ip_header = ip_hdr(skb);
    if (!ip_header){
        printk(KERN_INFO "Accepting a non-IP packet.");
        return NF_ACCEPT;
    }

    src_ip = ip_header->saddr;
    dst_ip = ip_header->daddr;
    protocol = ip_header->protocol;

    if (protocol != PROT_ICMP &&  protocol != PROT_TCP && protocol != PROT_ICMP){
        printk(KERN_INFO "Accepting an unsupported protocol.");
        return NF_ACCEPT;
    }

    printk(KERN_INFO "Protocol: %u", protocol);
    extract_transport_fields(skb, protocol, &src_port, &dst_port, &syn, &ack, &fin, &rst, &is_christmas_packet);

    if (protocol == PROT_TCP){
        printk (KERN_INFO "TCP Packet flags:\n SYN = %d   ACK = %d   RST = %d   FIN = %d", syn, ack, rst, fin);
    }

    packet_identifier.src_ip = src_ip;
    packet_identifier.dst_ip = dst_ip;
    packet_identifier.src_port = src_port;
    packet_identifier.dst_port = dst_port;
    
    printk(KERN_INFO "Processing this packet:");
    print_packet_identifier(&packet_identifier);

    log_entry = init_log_entry(packet_identifier, protocol);  

    if (is_christmas_packet) {
        log_entry.reason = REASON_XMAS_PACKET;
        log_entry.action = NF_DROP;
        add_or_update_log_entry(&log_entry);
        return NF_DROP;
    }


    if (protocol == PROT_TCP ) 
        handle_tcp_pre_routing(skb, state, packet_identifier, &log_entry, &verdict, syn, ack, rst, fin, direction);
    else
        hanlde_non_tcp_pre_routing(packet_identifier, &log_entry, &verdict, protocol, direction);
    
    add_or_update_log_entry(&log_entry);
    return verdict;
}

static unsigned int module_hook_local_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    tcp_data_t* tcp_data;
    packet_identifier_t packet_identifier;
    direction_t dir = get_direction_outgoing(state);
    int ret = 0;

    ip_header = ip_hdr(skb);
    if (!ip_header || !(ip_header->protocol == PROT_TCP))
        return NF_ACCEPT;

    tcp_data = get_tcp_data(skb);
    if (!tcp_data) {
        printk(KERN_ERR "Accepting non-TCP packets");
        return NF_ACCEPT;
    }
    packet_identifier.src_ip = ip_header->saddr;
    packet_identifier.dst_ip = ip_header->daddr;
    packet_identifier.src_port = tcp_data->src_port;
    packet_identifier.dst_port = tcp_data->dst_port;

    if(tcp_data->src_port == LOC_HTTP_PORT   || tcp_data->dst_port == HTTP_PORT || 
        tcp_data->src_port == LOC_FTP_PORT   || tcp_data->dst_port == FTP_PORT  ||
        tcp_data->src_port  == LOC_SMTP_PORT || tcp_data->dst_port == SMTP_PORT){
        printk(KERN_INFO "\n\n********************\n\n");
        printk(KERN_INFO "Packet @ LOCAL_OUT");
        printk(KERN_INFO "\n");
        printk(KERN_INFO "packet identifier:\n");
        print_tcp_packet(skb);
        ret = handle_mitm_local_out(skb, &packet_identifier, tcp_data, dir);
        if (ret < 0){
            printk(KERN_CRIT "Dropping local_out packet\n");
            return NF_DROP;
        }
        printk(KERN_CRIT "\nMITM - Modifed @ local out to:\n");
        print_tcp_packet(skb);
    }
    return NF_ACCEPT;
}



static unsigned int module_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned int verdict = NF_DROP;
    struct iphdr *ip_header;
    ip_header = ip_hdr(skb);
    if (!ip_header) {
        printk(KERN_INFO "\nAccepting for NON-IPv4 packets\n");
        return NF_ACCEPT; // Accept non-IPv4 packets (e.g., IPv6)
    }

    // Check for loopback packets (127.0.0.1/8)
    if ((ntohl(ip_header->saddr) & 0xFF000000) == 0x7F000000) {
        printk(KERN_INFO "\nAccepting for 127.0.0.1\n");
        return NF_ACCEPT; // Accept loopback packets without logging
    }

    // Accept any non-TCP, UDP, or ICMP protocol without logging
    if (ip_header->protocol != PROT_TCP && ip_header->protocol != PROT_UDP && ip_header->protocol != PROT_ICMP) {
        return NF_ACCEPT;
    }

    printk(KERN_INFO "\n\n************\nRecieved a new packet *************\n\n\n");

    verdict = get_packet_verdict_pre_routing(skb, state);
    printk(KERN_INFO "\n\n\nEnd packet <- %s \n************\n\n", verdict ? "Accept": "Drop");
    return verdict;
}



static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_logs);
static DEVICE_ATTR(conns, S_IRUSR, read_connections_table, NULL);
static DEVICE_ATTR(mitm, S_IWUSR, NULL, modify_mitm_port);

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_logs,
};


// Initialization function; handles error registering the hooks with cleanups and an indicative return value
static int __init fw_init(void) {    
    int ret;
    printk(KERN_INFO "\n\n\n\n\nLoading firewall module...!\n __V1.02__\n\n\n\n");
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


    conns_device = device_create(sysfs_class, NULL, MKDEV(major_number, 2), NULL, "conns");
    if (IS_ERR(conns_device))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return -1;
    }

    // Create the "conns" sysfs attribute for the "conns" device
    if (device_create_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 2));
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return -1;
    }

    mitm_device = device_create(sysfs_class, NULL, MKDEV(major_number, 3), NULL, "mitm");
    if (IS_ERR(mitm_device))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        device_destroy(sysfs_class, MKDEV(major_number, 2));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return -1;
    }

    // Create the "mitm" sysfs attribute for the "mitm" device
    if (device_create_file(mitm_device, (const struct device_attribute *)&dev_attr_mitm.attr))
    {
        device_destroy(sysfs_class, MKDEV(major_number, 3));
        device_destroy(sysfs_class, MKDEV(major_number, 2));
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
    netfilter_ops_fw.hooknum = NF_INET_PRE_ROUTING;
    netfilter_ops_fw.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &netfilter_ops_fw);
    if (ret) {
        printk(KERN_ERR "firewall: Failed to register forwarding hook. Error: %d\n", ret);
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        return ret;
    }

    // Set up the Netfilter hook for forwarding packets
    netfilter_ops_fw_local_out.hook = module_hook_local_out;
    netfilter_ops_fw_local_out.pf = PF_INET;
    netfilter_ops_fw_local_out.hooknum = NF_INET_LOCAL_OUT;
    netfilter_ops_fw_local_out.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &netfilter_ops_fw_local_out);
    if (ret) {
        printk(KERN_ERR "firewall: Failed to register LOCAL_OUT hook. Error: %d\n", ret);
        device_destroy(sysfs_class, MKDEV(major_number, 1));
        device_destroy(sysfs_class, MKDEV(major_number, 0));
        class_destroy(sysfs_class);
        unregister_chrdev(major_number, "fw_log");
        nf_unregister_net_hook(&init_net, &netfilter_ops_fw);
        return ret;
    }
    
    return 0;
}

static void __exit fw_exit(void)
{
    printk(KERN_INFO "Removing firewall module...\n");
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

    if (conns_device)
    {
        device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_conns.attr);
        device_destroy(sysfs_class, MKDEV(major_number, 2));
    }

    if (mitm_device)
    {
        device_remove_file(mitm_device, (const struct device_attribute *)&dev_attr_mitm.attr);
        device_destroy(sysfs_class, MKDEV(major_number, 3));
    }

    // Destroy the sysfs class (only after all devices are cleaned up)
    if (sysfs_class)
        class_destroy(sysfs_class);

    // Unregister the character device
    unregister_chrdev(major_number, "fw_log");

    // ****** Netfilter Cleanup ******
    nf_unregister_net_hook(&init_net, &netfilter_ops_fw);
    nf_unregister_net_hook(&init_net, &netfilter_ops_fw_local_out);

    printk(KERN_INFO "firewall module removed successfully.\n");
}

module_init(fw_init);
module_exit(fw_exit);