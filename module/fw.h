// TODO:
// Removing connection after termination and reset.
// Add a new device
// Refactor the code


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
#include <linux/inet.h>


// Testing
#include <linux/netfilter.h>

int DEV_MODE = 1;

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
#define IN_NET_DEVICE_NAME			"enp0s8"
#define EX_NET_DEVICE_NAME			"enp0s3"
#define OUT_NET_DEVICE_NAME			"enp0s9"

// auxiliary values, for your  convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(htons(1023))
#define MAX_RULES		(50)
#define RULE_NUM_FIELDS	(9)
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
	SYN_NO 		= 0x01,
	SYN_YES 	= 0x02,
	SYN_ANY 	= SYN_NO | SYN_YES,
} syn_t;

typedef enum {
	FIN_NO 		= 0x01,
	FIN_YES 	= 0x02,
	FIN_ANY 	= FIN_NO | FIN_YES,
} fin_t;

typedef enum {
	RST_NO 		= 0x01,
	RST_YES 	= 0x02,
	RST_ANY 	= RST_NO | RST_YES,
} rst_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

typedef enum {
	STATE_LISTEN        = 0x01, // Server waiting for a connection request
	STATE_SYN_SENT      = 0x02, // Client sent SYN, waiting for SYN-ACK
	STATE_SYN_RECEIVED  = 0x03, // Server received SYN, sent SYN-ACK, waiting for ACK
	STATE_ESTABLISHED   = 0x04, // Connection is established, data transfer allowed
	STATE_FIN_WAIT_1    = 0x05, // Active close initiated, FIN sent, waiting for ACK or FIN
	STATE_FIN_WAIT_2    = 0x06, // FIN acknowledged, waiting for peer's FIN
	STATE_CLOSE_WAIT    = 0x07, // FIN received, waiting for application to close
	STATE_CLOSING       = 0x08, // Both sides sent FIN, waiting for ACK
	STATE_LAST_ACK      = 0x09, // Passive close, waiting for final ACK
	STATE_TIME_WAIT     = 0x0A, // Waiting to ensure all packets are accounted for
	STATE_CLOSED        = 0x0B  // Connection is fully closed
} tcp_state_t;

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

typedef struct {
	__be32	src_ip;
	__be32	dst_ip;
	__be16	src_port;  
	__be16	dst_port; 
} packet_identifier_t;

typedef struct {
	packet_identifier_t packet;
	tcp_state_t	state;   			
} connection_rule_t;

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

#endif // _FW_H_