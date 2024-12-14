#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Testing
#include <linux/netfilter.h>



// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;


// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;
	

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)
#define IP_ANY 		    (htonl(0x00000000))

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
} minor_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_t;

// Testing
rule_t telnet2_rule;
rule_t default_rule;

// Set rule name


// Set rule name


rule_t telnet2_rule = {
	.rule_name = "telnet2_rule",
	.direction = DIRECTION_ANY, // Adjust based on your system's direction_t enum
	.src_ip = htonl(0x0A000101), // 10.0.1.1
	.src_prefix_mask = htonl(0xFFFFFF00), // 255.255.255.0
	.src_prefix_size = 24,
	.dst_ip = IP_ANY, // 0.0.0.0
	.dst_prefix_mask = IP_ANY, // 0.0.0.0
	.dst_prefix_size = 0,
	.src_port = htons(23),      // Source port 23
	.dst_port = htons(1023),   // Any port > 1023 (use special logic in filtering)
	.protocol = PROT_TCP,
	.ack = ACK_YES,
	.action = NF_ACCEPT, // NF_ACCEPT
};

rule_t default_rule = {
.rule_name = "default",
.direction = DIRECTION_ANY, 
.src_ip = htons(PORT_ANY),
.src_prefix_mask = htons(PORT_ANY),
.src_prefix_size = 0,
.dst_ip = IP_ANY, 
.dst_prefix_mask = IP_ANY,
.dst_prefix_size = 0,
.src_port = htons(PORT_ANY),
.dst_port = htons(PORT_ANY),
.protocol = PROT_ANY,
.ack = ACK_ANY,
.action = NF_DROP,
};




rule_t RULES[2];
RULES[0]=default_rule;
RULES[1]= telnet2_rule;


#endif // _FW_H_