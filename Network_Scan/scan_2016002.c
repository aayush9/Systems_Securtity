#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include<sys/wait.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

const int SRC_PORT = 4242;
#define MAX_ITER 1
int conn;

char *destination;

int  success[1<<16];

int TYPE_OF_SCAN;

struct meta{
	struct in_addr saddr;
	struct in_addr daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t tcp_len;
} *pseudo;

unsigned short csum(const short *msg, int len){
	uint32_t sum = 0;
	uint16_t *currword = (uint16_t*) msg;
	for(;len>1;len-=2) sum += *currword++;
	if(len>0) sum += *(uint8_t*) currword;
	sum = (sum>>16)+(sum&0xffff);
	sum += sum>>16;
	return (short)~sum;
}

int send_to_port(int port){
	unsigned char *buffer = malloc(100005);

	// Reference: https://www.exploit-db.com/papers/13025
	struct tcphdr *tcp = (struct tcphdr *) (buffer+ sizeof(struct iphdr));
	tcp->th_sport = htons(SRC_PORT);
	tcp->th_dport = htons(port);
	tcp->th_seq = rand();
	tcp->th_off = sizeof(*tcp)/4;
	if(TYPE_OF_SCAN == 0)
		tcp->th_flags = TH_SYN; //
	else if(TYPE_OF_SCAN == 1)
		tcp->th_flags = TH_FIN;
	tcp->th_win = htons(1024);

	pseudo = (struct meta*)((unsigned char *)tcp-sizeof(struct meta));
	inet_aton("10.211.55.25",&(pseudo->saddr));
	inet_aton(destination,&(pseudo->daddr));
	pseudo->proto = IPPROTO_TCP;
	pseudo->tcp_len = htons(sizeof(struct tcphdr));
	tcp->th_sum = csum((unsigned short *) pseudo, sizeof(struct meta)+sizeof(struct tcphdr));
		
	struct iphdr *iph = (struct iphdr *)buffer;
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = htons(sizeof(*iph)+sizeof(*tcp));
	iph->id = htons(random());
	iph->ttl = IPDEFTTL;
	iph->protocol = IPPROTO_TCP;
	iph->daddr = inet_addr(destination);
	iph->saddr = inet_addr("10.211.55.25");

	struct sockaddr_in server;
	server.sin_addr.s_addr = inet_addr(destination);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	int bytes;
	if(TYPE_OF_SCAN!=2)
		bytes = sendto(conn,buffer, sizeof(*tcp)+sizeof(*iph),0,(struct sockaddr*)&server,sizeof server);
	else
		bytes = sendto(conn,"\n", 1,0,(struct sockaddr*)&server,sizeof server);
	if(bytes < 0) return -1;
	return 0;
}

int recv_tcp(int port){
	unsigned char buffer[100005];
	struct sockaddr_in server;
	int server_len = sizeof server;

	while(1){
		int bytes = recvfrom(conn,buffer,sizeof buffer,0,(struct sockaddr*)&server,&server_len);
		if(TYPE_OF_SCAN==1){
			if(bytes<0)
				success[port]++;
			break;
		}
		if(bytes < 0) return -1;
		struct iphdr *ip = (struct iphdr*) buffer;
		struct tcphdr *tcp = (struct tcphdr*) (buffer + sizeof(struct iphdr));
		
		if(ip->protocol != IPPROTO_TCP) continue;

		if (server.sin_addr.s_addr != inet_addr(destination))
			continue;

		if (!(tcp->th_flags & TH_SYN)) continue;

		success[ntohs(tcp->th_sport)]++;
	}
}

int recv_udp(int port){
	unsigned char buffer[100005];
	struct sockaddr_in server;
	int server_len = sizeof server;

	int bytes = recvfrom(conn,buffer,sizeof buffer,0,(struct sockaddr*)&server,&server_len);
	if(bytes >= 0) return -1;
	struct icmp *icmp = (struct icmp*) (buffer + sizeof(struct iphdr));
	if((icmp->icmp_type == ICMP_UNREACH) && (icmp->icmp_code == ICMP_UNREACH_PORT)){
		success[port]++;
	}
}


int main(int argc, char *argv[]){
	if(argc<2) 
		return printf("Enter search IP as CLI argument\n"), 0;

	destination = malloc(1024);
	strcpy(destination,argv[1]);


	int range_begin = 1, range_end = 1000;
	if(argc>=3){
		int dash = 0;
		for(int i=0;argv[2][i];++i) if(argv[2][i]=='-')
			dash = i;
		range_begin = atoi(argv[2]);
		range_end = atoi(argv[2]+dash+1);
	}

	if(argc >= 4){
		if(!strcmp(argv[3],"-sF")) TYPE_OF_SCAN = 1;
		if(!strcmp(argv[3],"-sU")) TYPE_OF_SCAN = 2;
	}

	for(int i=range_begin; i<=range_end; ++i){

		for(int iter=0;iter<MAX_ITER;++iter){
			if(TYPE_OF_SCAN!=2) {
				if((conn = socket(AF_INET,SOCK_RAW,IPPROTO_RAW))==-1){
					printf("Could not create sending socket for port %d\n", i);
					continue;
				}
			} else {
				if((conn = socket(AF_INET,SOCK_DGRAM,0))==-1){
					printf("Could not create sending socket for port %d\n", i);
					continue;
				}
			}
			
			send_to_port(i);
			close(conn);

			if(TYPE_OF_SCAN!=2) {
				if((conn = socket(AF_INET,SOCK_RAW,IPPROTO_TCP))==-1){
					printf("Could not create receving socket for port %d\n", i);
					continue;
				}
			} else {
				if((conn = socket(AF_INET,SOCK_RAW,1))==-1){
					printf("Could not create receving socket for port %d\n", i);
					continue;
				}
			}

			struct timeval tle;
			if(TYPE_OF_SCAN!=2){
				usleep(1000);
				tle.tv_sec = 0; tle.tv_usec = 100;
				setsockopt(conn,SOL_SOCKET,SO_RCVTIMEO,&tle,sizeof tle);
				recv_tcp(i);
			} else{
				usleep(10000);
				tle.tv_sec = 0; tle.tv_usec = 10;
				setsockopt(conn,SOL_SOCKET,SO_RCVTIMEO,&tle,sizeof tle);
				recv_udp(i);
			}
			close(conn);
		}
	}
	int open_ports = 0;
	printf("PORT   STATE\n");
	for(int i=range_begin;i<=range_end;++i)
		if(success[i] == MAX_ITER){
			if(TYPE_OF_SCAN)
				printf("%d    Open|filtered\n", i);
			else
				printf("%d    Open\n", i);
			++open_ports;
		}
	printf("%d of %d ports open\n", open_ports, range_end-range_begin+1);
}