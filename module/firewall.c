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
struct device *conns_device;

// Define packet_log struct
struct packet_log {
    log_row_t log_object;       // The log entry object
    struct klist_node node;     // Node for inclusion in the klist
};

// Define connection_row struct for connections_table
struct connection_rule_row {
    connection_rule_t connection_rule_srv;       
    connection_rule_t connection_rule_cli;       
    struct klist_node node;
};

// Define the static klist for packet logs
static struct klist packet_logs = KLIST_INIT(packet_logs, NULL, NULL);
static int logs_num = 0;


// Define the static klist for packet logs
static struct klist connections_table = KLIST_INIT(connections_table, NULL, NULL);

// Netfilter hooks for relevant packet phases
static struct nf_hook_ops netfilter_ops_fw;

static int RULES_COUNT = 0;
static rule_t* FW_RULES;


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

void print_connection( struct connection_rule_row *entry){
            printk(KERN_INFO
               "Src_IP=%pI4, Dst_IP=%pI4, Src_Port=%u, Dst_Port=%u, "
               "State=%u",
               &entry->connection_rule_srv.packet.src_ip,
               &entry->connection_rule_srv.packet.dst_ip,
               ntohs(entry->connection_rule_srv.packet.src_port),
               ntohs(entry->connection_rule_srv.packet.dst_port),
               entry->connection_rule_srv.state);
            printk(KERN_INFO
               "Src_IP=%pI4, Dst_IP=%pI4, Src_Port=%u, Dst_Port=%u, "
               "State=%u",
               &entry->connection_rule_cli.packet.src_ip,
               &entry->connection_rule_cli.packet.dst_ip,
               ntohs(entry->connection_rule_cli.packet.src_port),
               ntohs(entry->connection_rule_cli.packet.dst_port),
               entry->connection_rule_cli.state);
}

void print_connections_table(void) {
    struct klist_iter iter;
    struct klist_node *knode;
    struct connection_rule_row *entry;

    printk(KERN_INFO "=== Printing Connecitnos Table Logs ===\n");

    // Initialize the iterator for the klist
    klist_iter_init(&connections_table, &iter);

    // Iterate over the klist
    while ((knode = klist_next(&iter))) {
        entry = container_of(knode, struct connection_rule_row, node);
        print_connection(entry);
    }

    // Exit the iterator
    klist_iter_exit(&iter);

    printk(KERN_INFO "=== End of Connectinos Table ===\n");
}


static ssize_t read_connections_table(struct device *dev, struct device_attribute *attr, char *buf) {
    struct klist_iter iter;
    struct klist_node *knode;
    struct connection_rule_row *entry;
    size_t offset = 0;
    char temp_buffer[128];
    ssize_t len;

    klist_iter_init(&connections_table, &iter);

    while ((knode = klist_next(&iter)) != NULL) {
        entry = container_of(knode, struct connection_rule_row, node);
        len = snprintf(temp_buffer, sizeof(temp_buffer),
                       "%pI4,%u,%pI4,%u,%u\n",
                       &entry->connection_rule_srv.packet.src_ip,
                       ntohs(entry->connection_rule_srv.packet.src_port),
                       &entry->connection_rule_srv.packet.dst_ip,
                       ntohs(entry->connection_rule_srv.packet.dst_port),
                       entry->connection_rule_srv.state);

        if (len < 0 || offset + len >= PAGE_SIZE) {
            break;
        }

        memcpy(buf + offset, temp_buffer, len);
        offset += len;

        len = snprintf(temp_buffer, sizeof(temp_buffer),
                       "%pI4,%u,%pI4,%u,%u\n",
                       &entry->connection_rule_cli.packet.src_ip,
                       ntohs(entry->connection_rule_cli.packet.src_port),
                       &entry->connection_rule_cli.packet.dst_ip,
                       ntohs(entry->connection_rule_cli.packet.dst_port),
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

static struct connection_rule_row* find_connection_row(packet_identifier_t packet_identifier){
    struct klist_iter iter;
    struct klist_node *knode;
    struct connection_rule_row *existing_entry;
    int counter = 0;

    // Initialize an iterator for the klist
    klist_iter_init(&connections_table, &iter);

    // Iterate over the klist to find a matching entry
    while ((knode = klist_next(&iter))) {
        existing_entry = container_of(knode, struct connection_rule_row, node);
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

static int initiate_connection(packet_identifier_t packet_identifier) {
    struct connection_rule_row* found_connection = find_connection_row(packet_identifier);
    if (found_connection != NULL)
        return NF_DROP;

    // Allocate memory for reversed_packet_identifier
    packet_identifier_t *reversed_packet_identifier = kmalloc(sizeof(packet_identifier_t), GFP_KERNEL);
    if (!reversed_packet_identifier) {
        printk(KERN_ERR "Memory allocation failed for reversed_packet_identifier\n");
        return NF_DROP;
    }
    reverse_packet_identifier(&packet_identifier, reversed_packet_identifier);

    // Allocate memory for new_rule_sender and new_rule_reciever
    struct connection_rule_row *new_rule_sender = kmalloc(sizeof(struct connection_rule_row), GFP_KERNEL);
    if (!new_rule_sender) {
        printk(KERN_ERR "Memory allocation failed for new_rule_sender\n");
        kfree(reversed_packet_identifier);
        kfree(new_rule_sender);
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

    // Add the new entries to the klist
    klist_add_tail(&new_rule_sender->node, &connections_table);

    print_connections_table();
    return NF_ACCEPT;
}

// Removes the connection from the klist connections_table 
static int remove_connection_row(struct connection_rule_row *connection) {
    if (!connection) {
        printk(KERN_ERR "remove_connection_row: NULL connection pointer\n");
        return -EINVAL;  // Return error for invalid argument
    }

    // Remove the node from the klist
    klist_remove(&connection->node);

    kfree(connection);

    printk(KERN_INFO "Connection successfully removed from the klist\n");
    print_connections_table();
    return 0;  // Success
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


static int handle_fin_state(struct connection_rule_row* connection, connection_rule_t* rule, 
                            int sender, int rule_owner, tcp_state_t others_state, __u8 ack, __u8 fin){
    int packet_sent = (sender == rule_owner);
    char* terminator = (sender == 0) ? "srv": "cli";
        switch (rule->state) {
            case STATE_ESTABLISHED:
                if (fin == FIN_YES && (packet_sent)) {
                    printk(KERN_CRIT "%s is terminating the session");
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Established -> Wait_1", terminator);
                    rule->state = STATE_FIN_WAIT_1;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                if (fin == FIN_NO && ack == ACK_YES &&
                    packet_sent && others_state == STATE_FIN_WAIT_1)
                {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Established -> Close_Wait", terminator);
                    rule->state = STATE_CLOSE_WAIT;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;

            case STATE_FIN_WAIT_1:
                if (ack == ACK_YES && fin == FIN_NO && !packet_sent) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_1 -> Wait_2", terminator);
                    rule->state = STATE_FIN_WAIT_2;
                    print_connections_table();
                    return NF_ACCEPT;
                } else if (fin == FIN_YES && !packet_sent) { // Handle simultanuous closing.....
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_1 -> Closing", terminator);
                    rule->state = STATE_CLOSING;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;

            case STATE_FIN_WAIT_2:
                if (ack == ACK_YES && packet_sent) { // Received fin and responded with ack.
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Wait_2 -> Time_wait", terminator);
                    rule->state = STATE_CLOSED;
                    print_connections_table();
                    return NF_ACCEPT;
                }
                break;

            case STATE_CLOSING:
                if (ack == ACK_YES && !packet_sent) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Closing -> Time_wait", terminator);
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
                if (ack == ACK_YES && !packet_sent) {
                    printk(KERN_INFO "STATCE_MACHINE_%s: Accepting for Last_ACK -> Closed", terminator);
                        rule->state = STATE_CLOSED;
                        // remove_connection_row(connection);
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
                                    struct connection_rule_row* found_connection, 
                                    __u8 syn, __u8 ack, __u8 rst, __u8 fin) {
    connection_rule_t* srv_rule = &found_connection->connection_rule_srv;
    connection_rule_t* cli_rule = &found_connection->connection_rule_cli;
    int sender_client = compare_packets(packet_identifier, cli_rule->packet);
    int srv_verdict, cli_verdict;
    // Handle RST (Reset): Always drop connection on RST
    if (rst == RST_YES) {
        srv_rule->state = STATE_CLOSED;
        cli_rule->state = STATE_CLOSED;
        printk(KERN_INFO "STATCE_MACHINE_srv: Accepting for rst = 1");
        print_connections_table();
        // remove_connection_row(found_connection);
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
            srv_verdict = handle_fin_state(found_connection, srv_rule, sender_client, 0, cli_rule->state, ack, fin);
    }

    // Handle client-side state transitions
    switch (cli_rule->state) {
        case STATE_SYN_SENT:
            if ((srv_rule->state == STATE_SYN_RECEIVED || srv_rule->state == STATE_ESTABLISHED) && 
                sender_client && syn == SYN_NO && ack == ACK_YES) {
                    printk(KERN_INFO "STATCE_MACHINE_cli: Accepting for STATE_SYN_SENT -> Established");
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
            cli_verdict = handle_fin_state(found_connection, cli_rule, sender_client, 1, srv_rule->state, ack, fin);
    }

    return (srv_verdict == NF_ACCEPT || cli_verdict == NF_ACCEPT) ? NF_ACCEPT : NF_DROP;
}


// Given a TCP/UDP/ICMP packet
static int get_packet_verdict(struct sk_buff *skb, const struct nf_hook_state *state) {
    __be32 src_ip = 0, dst_ip = 0;
    __be16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;
    __u8 ack, syn, fin, rst;
    struct iphdr *ip_header;
    direction_t direction;
    int is_christmas_packet = 0, found_rule_index;
    log_row_t log_entry;
    packet_identifier_t packet_identifier;

    memset(&log_entry, 0, sizeof(log_row_t)); // Initialize to zero
    direction = strcmp(state->in->name, IN_NET_DEVICE_NAME) == 0 ? DIRECTION_IN : DIRECTION_OUT;

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

    extract_transport_fields(skb, protocol, &src_port, &dst_port, &syn, &ack, &fin, &rst, &is_christmas_packet);
    printk (KERN_INFO "TCP Packet flags:\n SYN = %d   ACK = %d   RST = %d   FIN = %d", syn, ack, rst, fin);

    packet_identifier.src_ip = src_ip;
    packet_identifier.dst_ip = dst_ip;
    packet_identifier.src_port = src_port;
    packet_identifier.dst_port = dst_port;
    
    printk(KERN_INFO "Processing this packet:");
    print_packet_identifier(&packet_identifier);

    log_entry.timestamp = jiffies;           // Use jiffies as the timestamp
    log_entry.protocol = protocol;          // Protocol extracted from the IP header
    log_entry.src_ip = src_ip;              // Source IP from the packet
    log_entry.dst_ip = dst_ip;              // Destination IP from the packet
    log_entry.src_port = src_port;          // Source port from transport fields
    log_entry.dst_port = dst_port;          // Destination port from transport fields
    log_entry.count = 1;                    // Initial hit count       

    if (is_christmas_packet) {
        log_entry.reason = REASON_XMAS_PACKET;
        log_entry.action = NF_DROP;
        add_or_update_log_entry(&log_entry);
        return NF_DROP;
    }

    // Stateless Inspection
    if (ack == ACK_NO){
        printk(KERN_INFO "Packet with ack = 0");
        found_rule_index = comp_packet_to_static_rules(packet_identifier, protocol, ack, direction);
        if (found_rule_index >= 0) {
            if (protocol == PROT_TCP  && FW_RULES[found_rule_index].action){
                printk(KERN_INFO "Initiating a new connection");
                // Try establishing a new connection for TCP packets - drop if invalid connection.
                if(!initiate_connection(packet_identifier)){
                    printk(KERN_ERR "Connection could not be intiated");
                    log_entry.action = NF_DROP;
                    log_entry.reason = REASON_ILLEGAL_VALUE;
                    add_or_update_log_entry(&log_entry);
                    return NF_DROP;
                }
            }
            log_entry.action = FW_RULES[found_rule_index].action;      
            log_entry.reason = found_rule_index;   
            add_or_update_log_entry(&log_entry);
            return FW_RULES[found_rule_index].action;
        }

        log_entry.action = NF_DROP;
        log_entry.reason = REASON_NO_MATCHING_RULE;   
        printk(KERN_INFO "\nDropping - No static match");
        add_or_update_log_entry(&log_entry);
        return NF_DROP;
    } else if (ack == ACK_YES && protocol == PROT_TCP) {
        printk(KERN_INFO "**Handling a dynamic packet..");
        struct connection_rule_row* found_connection = find_connection_row(packet_identifier);
        if (found_connection == NULL){
            printk (KERN_INFO "\n\nNo connecition found in the table. DROPPING.\n\n");
            return NF_DROP;
        } else {
            printk (KERN_INFO "Connection found. Comparing agains TCP state machine.\n");
            return handle_tcp_state_machine(packet_identifier, found_connection, syn, ack, rst, fin);
        }
    }
    return NF_DROP;
}

static unsigned int module_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    unsigned int verdict = NF_DROP;
    struct iphdr *ip_header;
    ip_header = ip_hdr(skb);
    // Accept external incoming packets (** FOR DEV MODE ONLY **) 
    if (DEV_MODE && (strcmp(state->in->name, EX_NET_DEVICE_NAME) == 0 || 
        strcmp(state->in->name, EX_NET_DEVICE_NAME) == 0) ){
        printk(KERN_INFO "(DEV) Accepting External Packet ");
        return NF_ACCEPT;
    }
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

    printk(KERN_INFO "\n\n************\nRecieved a new packet \n************\n\n");

    verdict = get_packet_verdict(skb, state);
    return verdict;
}



static DEVICE_ATTR(rules, S_IWUSR | S_IRUGO , display_rules, modify_rules);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_logs);
static DEVICE_ATTR(conns, S_IRUSR, read_connections_table, NULL);

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = read_logs,
};


// Initialization function; handles error registering the hooks with cleanups and an indicative return value
static int __init fw_init(void) {    
    int ret;
    printk(KERN_INFO "\n\n\n\n\nLoading firewall module...!\n\n\n\n\n");
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
        device_remove_file(conns_device, (const struct device_attribute *)&dev_attr_reset.attr);
        device_destroy(sysfs_class, MKDEV(major_number, 2));
    }

    // Destroy the sysfs class (only after all devices are cleaned up)
    if (sysfs_class)
        class_destroy(sysfs_class);

    // Unregister the character device
    unregister_chrdev(major_number, "fw_log");

    // ****** Netfilter Cleanup ******
    nf_unregister_net_hook(&init_net, &netfilter_ops_fw);

    printk(KERN_INFO "firewall module removed successfully.\n");
}

module_init(fw_init);
module_exit(fw_exit);