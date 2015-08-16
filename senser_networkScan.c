#include "senser_networkScan.h"

int traffic_flag = 0;

void *networkScan(void *arg)
{
	bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
	struct bpf_program filter;        /* Place to store the BPF filter program  */ 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	pcap_t *descr = NULL;             /* Network interface handler              */
	char *ethernet = DEVICENAME;
	device_info dev_info;				/*my ethernet address*/
	device_info gate_info;
	NodeStatus node_status;			//노드 정보
	network_grub_args *n_args = 0;
	sendkill_grub_args k_args;

	pthread_t t_id1 = 0;
	pthread_t t_id2 = 0;
	int state1 = 0;
	int state2 = 0;
	receiver_grub_args grub;
	int i;

	memset(&node_status, 0, sizeof(NodeStatus));

	n_args = (network_grub_args*)arg;

	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	/* Open network device for packet capture */ 
	if ((descr = pcap_open_live(ethernet, MAXBYTES2CAPTURE, 0,  512, errbuf))==NULL){
		fprintf(stderr, "1ERROR: %s\n", errbuf);
		exit(1);
	}

	/* Look up info from the capture device. */ 
	if( pcap_lookupnet(ethernet , &netaddr, &mask, errbuf) == -1){
		fprintf(stderr, "2ERROR: %s\n", errbuf);
		exit(1);
	}

	/* Compiles the filter expression into a BPF filter program */ 
	if ( pcap_compile(descr, &filter, "tcp or arp", 1, mask) == -1){
		fprintf(stderr, "3ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	/* Load the filter program into the packet capture device. */ 
	if (pcap_setfilter(descr,&filter) == -1){
		fprintf(stderr, "4ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	get_device_info(&dev_info);

	k_args.n_args = n_args;
	k_args.gate_info = &gate_info;
	k_args.descr = descr;

	while(1) {			/* get gateway*/
		const unsigned char *packet = NULL; //packet
		struct pcap_pkthdr *p_pkthdr = 0;

		packet = make_arp_packet(dev_info, n_args->g_ip);

		pcap_sendpacket(descr, packet, 42);
		if (pcap_next_ex(descr, &p_pkthdr, &packet) != 1) {
			continue;
		}
		if(gateway_get(packet, n_args->g_ip, k_args.gate_info))
			break;
	}

	printf("GateWay MAC: ");
	for(i=0; i<6;i++) {
		printf("%02X:", k_args.gate_info->macaddr[i]);
	}

	printf("\nGateWay IP: ");
	for(i=0; i<4;i++) {
		printf("%d.", k_args.gate_info->ipaddr[i]);
	}
	puts("");

	grub.p_descr = descr;
	grub.p_node_status = &node_status;
	memcpy( (char*)&grub+8, (unsigned char*)&dev_info+6, 4);

	state1 = pthread_create(&t_id1, NULL, receiver, &grub);
	// puts("thread start");
	if (state1 != 0) {
		fprintf(stderr, "pthread_create() error\n");
		return 0;
	}

	state2 = pthread_create(&t_id2, NULL, send_kill_packet, &k_args);
	// puts("thread start");
	if (state2 != 0) {
		fprintf(stderr, "pthread_create() error\n");
		return 0;
	}

	// puts("thread start2");
	while(1) {
		int node_cnt = 0;
		traffic_flag = 0;
		memset(&node_status, 0, sizeof(NodeStatus));
		send_arp_packet(descr, dev_info);
		
		sleep(3);
		printf("\nNetwork Node Status!!!!\n");
		for(i=1; i<255; i++) {
			if(node_status.node[i].status == 1) {
				printf("%c[1;34m",27);
				printf("%5d", i);
				printf("%c[0m",27);
				node_cnt++;
			} else {
				printf("%5d", 0);
			}

			if(i%15 == 0)
				puts("");
		}
		printf("\n_____________________________________________________________________________%d\n", node_cnt);

		traffic_flag = 1;

		sleep(10);
	}
	printf("main function exit\n");
	return 0;
}

void send_arp_packet(pcap_t *descr, device_info dev_info)
{
	int dest_ip;
	const unsigned char *packet = NULL;	//packet

	for(dest_ip=1; dest_ip<255; dest_ip++) {
		packet = make_arp_packet(dev_info, dest_ip);
		// print_packet(packet);
		pcap_sendpacket(descr, packet, 42);
		usleep(10000);
	}
}

unsigned char* make_arp_packet(device_info dev_info, u_char dest_last_addr)
{
	static unsigned char pack_data[42];
	etherhdr_t et_hdr;
	arphdr_t arp_hdr;

	/*ethernet*/
	memset(&et_hdr, 0xff, 6);			//et_hdr.h_dest[]
	memcpy((unsigned char*)&et_hdr+6, &dev_info, 6);	//et_hdr.h_source[]

	et_hdr.h_proto = htons(0x0806);
	
	/*arp*/
	memset(&arp_hdr, 0x00, sizeof(arphdr_t));		//init
	arp_hdr.htype = htons(0x0001);
	arp_hdr.ptype = htons(0x0800);
	arp_hdr.oper = htons(ARP_REQUEST);
	arp_hdr.hlen = 0x06;
	arp_hdr.plen = 0x04;
	memcpy((unsigned char*)&arp_hdr+8, &dev_info, 6);		//arp_hdr.sha[]
	memcpy((unsigned char*)&arp_hdr+14, (unsigned char*)&dev_info+6, 4);	//arp_hdr.sha[]
	memcpy((unsigned char*)&arp_hdr+24, (unsigned char*)&dev_info+6, 3);	//arp_hdr.tpa[3] 까지

	arp_hdr.tpa[3] = dest_last_addr;

	memset(pack_data, 0, sizeof(pack_data));
	memcpy(pack_data, &et_hdr, 14);
	memcpy(pack_data+14, &arp_hdr, 28);

	return pack_data;
}

int get_device_info(device_info *p_dev_info)
{
    // 이더넷 데이터 구조체 
    struct ifreq *ifr;
    struct sockaddr_in *sin;
    struct sockaddr *sa;

    // 이더넷 설정 구조체
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    memset(p_dev_info, 0, sizeof(device_info));


    // 이더넷 설정정보를 가지고오기 위해서 
    // 설정 구조체를 초기화하고  
    // ifreq데이터는 ifc_buf에 저장되며, 
    // 네트워크 장치가 여러개 있을 수 있으므로 크기를 충분히 잡아주어야 한다.  
    // 보통은 루프백주소와 하나의 이더넷카드, 2개의 장치를 가진다.
    memset(&ifcfg, 0, sizeof(ifcfg));
    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = malloc(ifcfg.ifc_len);

    while(1) {
        ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
        ifcfg.ifc_buf = realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0) {
            perror("SIOCGIFCONF ");
            return 1;
        }
        // 디버깅 메시지 ifcfg.ifc_len/sizeof(struct ifreq)로 네트워크 
        // 장치의 수를 계산할 수 있다.  
        // 물론 ioctl을 통해서도 구할 수 있는데 그건 각자 해보기 바란다.
        // printf("%d : %d \n", ifcfg.ifc_len, sizeof(struct ifreq));
        break;
    }

    // 주소를 비교해 보자.. ifcfg.ifc_req는 ifcfg.ifc_buf를 가리키고 있음을 
    // 알 수 있다. 
    // printf("address %p\n", &ifcfg.ifc_req);
    // printf("address %p\n", &ifcfg.ifc_buf);

    // 네트워크 장치의 정보를 얻어온다.  
    // 보통 루프백과 하나의 이더넷 카드를 가지고 있을 것이므로 
    // 2개의 정보를 출력할 것이다. 
    ifr = ifcfg.ifc_req;
    for (n = 0; n < ifcfg.ifc_len; n+= sizeof(struct ifreq)) {
        int i;
        char *p_temp;
        // 주소값을 출력하고 루프백 주소인지 확인한다.
        // printf("[%s]\n", ifr->ifr_name);
        if(strcmp(ifr->ifr_name, DEVICENAME) == 0) {
            sin = (struct sockaddr_in *)&ifr->ifr_addr;

            p_temp = strtok(inet_ntoa(sin->sin_addr), ".");
            for(i=0; p_temp != NULL; i++) {
                p_dev_info->ipaddr[i] = (unsigned char)atoi(p_temp);
                p_temp = strtok(NULL, ".");
            }

            // MAC을 출력한다.
            ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
            sa = &ifr->ifr_hwaddr;

            for(i=0; i<6; i++) {
                p_dev_info->macaddr[i] = (unsigned char)((int)sa->sa_data[i]);
            }            

            return 0;
        }
        ifr++;
    }

    return 1;
}

void *receiver(void *arg)
{
	int pipeFd = 0;
	const unsigned char *p_packet = 0;
	struct pcap_pkthdr *p_pkthdr = 0;

	receiver_grub_args *grub = (receiver_grub_args*)arg;
	pcap_t *p_descr = grub->p_descr;
	NodeStatus *p_node_status = grub->p_node_status;
	unsigned char *source_ip = 0;	
	source_ip = grub->source_ip;

/*	if ((pipeFd = open(".read_sense", O_RDWR)) < 0) {
		perror("fail to call open()");
		exit(1);
	}
*/
	while(1){
		if (pcap_next_ex(p_descr, &p_pkthdr, &p_packet) != 1) {
			continue;
		}

		/*if ((pipeFd = open(".read_sense", O_RDWR)) < 0) {
			perror("fail to call open()");
			exit(1);
		}*/



		/*if(traffic_flag == 1) {
			confirmNodeTraffic(p_packet, p_pkthdr, source_ip, pipeFd);
		}*/
		
		check_reply_packet(p_packet, p_pkthdr, source_ip, p_node_status, pipeFd);

		//close(pipeFd);
	}
	close(pipeFd);

	return 0;
}

int check_reply_packet(const unsigned char *packet, struct pcap_pkthdr *pkthdr, unsigned char *source_ip, NodeStatus *p_node_status, int pipeFd)
{
	etherhdr_t *ether = (etherhdr_t*)(packet);
	if(ntohs(ether->h_proto) != 0x0806)
		return 0;
	
	arphdr_t *arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
	char result[1024] = {0,};
	int writen;
	int i=0;
	
	if(ntohs(arpheader->oper) == ARP_REQUEST)
		return 0;

	if(memcmp(arpheader->tpa, source_ip, 4) != 0)
		return 0;

	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
		
		printf("\n Receiver IP: "); 
		for(i=0; i<4;i++)
			printf("%d.", arpheader->spa[i]);

		p_node_status->node[arpheader->spa[3]].status = 1;

		//sprintf(result,"echo D~%d.%d.%d.%d > .read_sense", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2], arpheader->spa[3]);

	}

	/*if ((writen = write(pipeFd, result, strlen(result))) < 0) {
		perror("write error");
		exit(1);
	}
	*/
	system(result);
	usleep(400);
	return 1; 

}

void confirmNodeTraffic(const unsigned char *packet, struct pcap_pkthdr *pkthdr, unsigned char *source_ip, int pipeFd)
{
	int writen;

	etherhdr_t *ether = (etherhdr_t*) (packet);
	if(ntohs(ether->h_proto) == 0x0800){
		struct ip *iphdr = (struct ip*) (packet+ sizeof(etherhdr_t));
		struct tcphdr *tcp = (struct tcphdr*) (packet+ sizeof(etherhdr_t) + sizeof(struct ip));

		unsigned char c_src_ip[4] = {0,};
		unsigned char c_dst_ip[4] = {0,};
		u_int n_ip_temp;
		u_char *p_c_ip;
		
		n_ip_temp = *((unsigned int*)(&(iphdr->ip_src)));		//Cu¹o?E?.
		p_c_ip = (u_char*) (&n_ip_temp);
		memcpy(&c_src_ip, p_c_ip, 4);

		n_ip_temp = *((unsigned int*)(&(iphdr->ip_dst)));		//Cu¹o?E?.
		p_c_ip = (u_char*) (&n_ip_temp);
		memcpy(&c_dst_ip, p_c_ip, 4);
		
		//printf("tcp dest port: %d\n", ntohs(tcp->dest));
		char result[1024] = {0,};
		
		if(c_src_ip[0] == 210 && c_src_ip[1] == 118 && c_src_ip[2] == 34){
			sprintf(result,"echo D@%d.%d.%d.%dL%dLu%dL%d.%d.%d.%d > .read_sense", c_src_ip[0], c_src_ip[1], c_src_ip[2], c_src_ip[3], ntohs(tcp->dest), pkthdr->len, c_dst_ip[0], c_dst_ip[1], c_dst_ip[2], c_dst_ip[3]);
			
		// printf("%d ", *((u_char*)(&n_ip_temp)+i) );
		}
		else{
			sprintf(result,"echo D@%d.%d.%d.%dL%dLd%dL%d.%d.%d.%d > .read_sense", c_dst_ip[0], c_dst_ip[1], c_dst_ip[2], c_dst_ip[3], ntohs(tcp->source), pkthdr->len, c_src_ip[0], c_src_ip[1], c_src_ip[2], c_src_ip[3]);
			
		}

		//printf("%s\n", result);
		/*if ((writen = write(pipeFd, result, strlen(result))) < 0) {
			perror("write error");
			exit(1);
		}*/
		system(result);
		usleep(300);

	}

}

/*test function*/
void print_packet(const unsigned char *packet)
{
	etherhdr_t *ether = (etherhdr_t*)(packet);
	arphdr_t *arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
	int i=0;

	puts("\n------Ethernet Headeer--------------------");
	printf("source= ");
	for(i=0; i<6;i++)
		printf("%02X:", ether->h_source[i]);

	printf("\ndest= ");
	for(i=0; i<6;i++)
		printf("%02X:", ether->h_dest[i]);

	printf("\nproto = %04x\n", ntohs(ether->h_proto));
	puts("------arp Header--------------");

	printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
	printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown"); 
	printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

	/*printf("Hardware type: %04x\n", ntohs(arpheader->htype));
	printf("Protocol type: %04x\n", ntohs(arpheader->ptype));
	printf("Operation: %04x\n", ntohs(arpheader->oper));*/
	printf("hlen: %02x\n", arpheader->hlen);
	printf("plen: %02x\n", arpheader->plen);

	/* If is Ethernet and IPv4, print packet contents */ 
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){ 
		printf("Sender MAC: "); 
			
		for(i=0; i<6;i++)
			printf("%02X:", arpheader->sha[i]); 

		printf("\nSender IP: "); 

		for(i=0; i<4;i++)
			printf("%d.", arpheader->spa[i]); 

		printf("\nTarget MAC: "); 

		for(i=0; i<6;i++)
			printf("%02X:", arpheader->tha[i]); 

		printf("\nTarget IP: "); 

		for(i=0; i<4; i++)
			printf("%d.", arpheader->tpa[i]); 

		printf("\n"); 
	} 

}
