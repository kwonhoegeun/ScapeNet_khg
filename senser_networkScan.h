#ifndef _NETWORKSCAN
#define _NETWORKSCAN
 
// #include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/epoll.h>
// #include <sys/stat.h>
// #include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "senser_protocol.h"
#include "senser_nodeKill.h"

#define MAXBYTES2CAPTURE 2048

typedef struct NodeInfo {
	int status;	//상태
	int openPorts[20]; //열린포트
	int traffics_up; //traffic 양
	int traffics_down; //traffic 양
} NodeInfo;

typedef struct NodeStatus {
	NodeInfo node[255];
} NodeStatus;

/*typedef struct killnode_list {
	u_char target_ip[255];
} killnode_list;

typedef struct network_grub_args {
	killnode_list k_list;
	u_char g_ip;
} network_grub_args;*/

typedef struct receiver_grub_args {
	pcap_t *p_descr;
	NodeStatus *p_node_status;
	unsigned char source_ip[4];
} receiver_grub_args;

void *networkScan(void *);
void send_arp_packet(pcap_t *, device_info);
unsigned char* make_arp_packet(device_info, u_char );

int get_device_info(device_info *);
void print_packet(const unsigned char *);

void *receiver(void *);
int check_reply_packet(const unsigned char *, struct pcap_pkthdr *, unsigned char *, NodeStatus *, int);
void confirmNodeTraffic(const unsigned char *, struct pcap_pkthdr *, unsigned char *, int);

#endif