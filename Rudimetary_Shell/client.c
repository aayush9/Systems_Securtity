#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

int conn, PORT=4257;

int main(int argc , char *argv[]) {
	struct sockaddr_in server;
	char identity[1005];
	
	if((conn=socket(AF_INET,SOCK_STREAM,0)) == -1) return printf("Could not create socket"), 1;
	server.sin_addr.s_addr = inet_addr("127.0.0.1"), server.sin_family = AF_INET, server.sin_port = htons(PORT);

	printf("Username: "); 
	fgets(identity,995,stdin);
	identity[strlen(identity)-1] = 0;
 
	if(connect(conn ,(struct sockaddr *)&server,sizeof(server))<0) return printf("connect failed. Error"), 1;
	if(send(conn, identity, strlen(identity),0)<0) return printf("Error connecting to server...\n"),0;
	for(char output[1005],input[1015];;){
		memset(output,0, sizeof output); memset(input,0, sizeof input);
		if(recv(conn, output, 1005,0)<=0) return printf("Can't receive message, server disconnected, exiting\n"),0;
		printf("%s",output);
		if(!strcmp(output,"Invalid credentials...\n")) return 0;
		fgets(input,1005,stdin);
		if(input[1004]) return printf("Suspicious input, exiting...\n"),-1;
		if(input[strlen(input)-1]=='\n') input[strlen(input)-1]=0;
		if(send(conn, input, strlen(input),0)<0) return printf("Can't send message, server disconnected, exiting\n"),0;
		if(!strcmp(input,"logout")||!strcmp(input,"exit")) break;
	}
	close(conn);
	return 0;
}