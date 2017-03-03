#ifndef _PROTOCOL
#define _PROTOCOL

#include <netinet/ip.h>
#include <netinet/tcp.h>

#define DEVICENAME "eth0"

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */

typedef struct etherhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	unsigned short h_proto;
} etherhdr_t;

typedef struct arphdr { 
	u_int16_t htype;    /* Hardware Type           */ 
	u_int16_t ptype;    /* Protocol Type           */ 
	u_char hlen;        /* Hardware Address Length */ 
	u_char plen;        /* Protocol Address Length */ 
	u_int16_t oper;     /* Operation Code          */ 
	u_char sha[6];      /* Sender hardware address */ 
	u_char spa[4];      /* Sender IP address       */ 
	u_char tha[6];      /* Target hardware address */ 
	u_char tpa[4];      /* Target IP address       */ 
}arphdr_t;

typedef struct device_info {
	unsigned char macaddr[6];
	unsigned char ipaddr[4];
} device_info;


#endif
