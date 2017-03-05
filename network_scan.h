#ifndef _NETWORKSCAN
#define _NETWORKSCAN

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include "node_kill.h"
#include "protocol.h"

#define MAXBYTES2CAPTURE 2048

typedef struct NodeStatus {
	int node[255];
} NodeStatus;

typedef struct receiver_grub_args {
	pcap_t *p_descr;
	NodeStatus *p_node_status;
	u_char source_ip[4];
	pthread_mutex_t mutex;
} receiver_grub_args;

void *networkScan(void *);
void send_arp_packet(pcap_t *, device_info);
u_char* make_arp_packet(device_info, u_char );

int get_device_info(device_info *, const char *);
void print_packet(const u_char *);

void *receiver(void *);
int check_reply_packet(const u_char *, struct pcap_pkthdr *,
			receiver_grub_args *);
#endif
