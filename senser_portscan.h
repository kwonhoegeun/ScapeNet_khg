#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

struct host {
    int sock;
    int status;
};

typedef struct portscan_grub_args {
	char *ip;
	int t_port;
	int repley;
} portscan_grub_args;

void usage(char *);
int scan(int, unsigned long, int);
int init_socket();
//int portscan(char*, char* ,int, int);
void portscan(void *);

