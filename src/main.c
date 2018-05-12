#include <stdio.h>
#include "network_scan.h"

#define BUFFER_SIZE 255

void receiver_fifo(network_grub_args *n_args);
int get_gateway_last_num(u_char *g_ip);

int main(int argc, char *argv[])
{
	network_grub_args n_args;
	pthread_t t_id;
	int ret;
	int i;

	printf("network Scaning\n");

	memset(&n_args, 0, sizeof(n_args));

	if (get_gateway_last_num(&n_args.g_ip) < 0)
		return 0;

	ret = pthread_create(&t_id, NULL, networkScan, &n_args);
	if (ret) {
		fprintf(stderr, "pthread_create() error\n");
		return 0;
	}

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			int t_ip = atoi(argv[i]);
			printf("%d\n",t_ip);
			n_args.k_list.target_ip[t_ip] = 1;
		}
	}
#if 0

	{	//dddddddddddddddddddddddddd
		int a;
		for (a=69; a<255; a++) {
			if (a==227 || a==207 || a==171)
				continue;
			n_args.k_list.target_ip[a] = 1;
		}
	}
#endif

	receiver_fifo(&n_args);

	return 0;
}

void receiver_fifo(network_grub_args *n_args)
{
	int pipeFd;
	int readn;
	char buffer[BUFFER_SIZE] = { 0, };
	char *token_order;
	u_char ip[4] = { 0, };

	if ((pipeFd = open(".write_sense", O_RDWR)) < 0) {
		perror("fail to call open()");
		exit(1);
	}

	/* pipe 데이터 기다리는 부분 */
	while (1) {
		if ((readn = read(pipeFd, buffer, BUFFER_SIZE)) < 0) {
			perror("read error");
			exit(1);
		}
		else {
			int flag_order = 0;
			buffer[strlen(buffer)-1] = '\0';

			/* head 분리*/
			token_order = strtok(buffer, " ");
			if (!strcmp(token_order, "k")) {
				puts("kill");
				flag_order = 1;
			} else if (!strcmp(token_order, "p")) {
				puts("pass");
				flag_order = 2;
			}
			token_order = strtok(NULL, " ");
			ip[3] = atoi(token_order);

			/* kill & pass */
			switch(flag_order) {
				case 1:
					printf("kill ip = %d\n",ip[3]);
					n_args->k_list.target_ip[ip[3]] = 1;
					break;
				case 2:
					printf("pass ip = %d\n",ip[3]);
					n_args->k_list.target_ip[ip[3]] = 0;
					break;
			}
		}
	}

	close(pipeFd);
}

int get_gateway_last_num(u_char *g_ip)
{
	char command[] = "route | grep default | awk -F' ' '{print $2}' | awk -F'.' '{print $4}'";
	char str[4];
	FILE *fp;
	int ret;

	fp = popen(command, "r");
	if (!fp) {
		fprintf(stderr, "file open error\n");
		return -1;
	}

	ret = fread((void *)str, sizeof(char), 4, fp);
	if (!ret) {
		fprintf(stderr, "file open error\n");
		ret = -1;
		goto err;
	}

	*g_ip = atoi(str);

err:
	pclose(fp);

	return ret;
}
