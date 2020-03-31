#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
# include <pwd.h>
#include <assert.h>
#include <sys/wait.h>

#include "crypt.c"

#define MAX_CONNECTIONS 4242

int clients[MAX_CONNECTIONS];
char shared_secret[4242][32];
char *logged_in[4242];

char *public_keys[4242];

unsigned char server_private_key[32] = "I am server";

struct group{
	int id;
	char name[42];
	int members[42];
};

struct group *groups[42];

int search_for_user(char uname[]){
	for(int i=1;i<MAX_CONNECTIONS;++i)
		if(logged_in[i] && !strcmp(uname, logged_in[i])) return i;
	return 0;
}


int send_to_user(char msg[], char uname[]){
	int idx, len = strlen(msg);
	if(!(idx=search_for_user(uname))) return -1;
	char now[1024];
	for(int i=0;i<1024;++i) now[i] = msg[i];
	enc(now,shared_secret[idx],1);
	send(clients[idx],now,1024, 0);
	return 0;
}

void broadcast(char msg[], int ignore){
	for(int i=1,len=strlen(msg);i<MAX_CONNECTIONS;++i) 
		if(i!=ignore&&clients[i]) send_to_user(msg,logged_in[i]);
}

void *manage_connection(void* index) {
	int idx = *((int *)index), received;
	unsigned char message[1024];
	while((received=recv(clients[idx],message,1024,0))>0){
		// for(int i=0;i<25;++i) printf("%d ", message[i]); puts("");
		enc(message,shared_secret[idx],0);
		if(message[0] == 0) continue;
		if(!strcmp(message,"/quit")){
			received = 0;
			break;
		}
		printf("Client(%s): %s\n", logged_in[idx], message);
		char **tokens = tokenize(message);
		unsigned char *output = malloc(1024);
		if(!strcmp(tokens[0],"/who")) {
			for(int i=1;i<MAX_CONNECTIONS;++i) if(logged_in[i])
				sprintf(output,"%s%s\n",output,logged_in[i]);
			send_to_user(output, logged_in[idx]);
		} else if(!strcmp(tokens[0],"/write_all")) {
			unsigned char *broadcast_msg = malloc(1024);
			for(int i=1;tokens[i];++i)
				sprintf(broadcast_msg,"%s %s",broadcast_msg,tokens[i]);
			sprintf(broadcast_msg,"%s\n", broadcast_msg);
			broadcast(broadcast_msg,idx);
			free(broadcast_msg);
		} else if(!strcmp(tokens[0],"/create_group")) {
			for(int i=1;i<42;++i) if(!groups[i]){
				groups[i] = (struct group*) malloc(sizeof(struct group));
				memset(groups[i]->name,0,sizeof groups[i]->name);
				groups[i]->id = i;
				sprintf(groups[i]->name,"Group_%d", i);
				groups[i]->members[0] = idx;
				for(int j=0;j<42;++j) groups[i]->members[j] = 0;
				groups[i]->members[0] = idx;
				sprintf(output, "Name: %s ID: %d\n",groups[i]->name, groups[i]->id);
				break;
			}
			send_to_user(output,logged_in[idx]);
		} else if(!strcmp(tokens[0],"/group_invite")) {
			sprintf(output,"Group invite received: %s\n", tokens[1]);
			for(int i=2;tokens[i];++i) {
				if(send_to_user(output,tokens[i]))
					printf("Invalid user name: %s, skipping...\n",tokens[i]);
			}
		} else if(!strcmp(tokens[0],"/group_invite_accept")) {
			int group_id;
			if(!tokens[1] || !(group_id=atoi(tokens[1]))) sprintf(output,"Invalid group id\n");
			else {
				for(int i=1;i<42;++i) if(groups[i] && groups[i]->id == group_id){
					for(int j=0;j<42;++j) if(!groups[i]->members[j]) {
						groups[i]->members[j] = idx;
						break;
					}
					sprintf(output,"Successfully joined\n");
					break;
				}
				if(strlen(output) == 0)
					sprintf(output,"No such group\n");
			}
			send_to_user(output,logged_in[idx]);
		}else if(!strcmp(tokens[0],"/write_user")){
			char *payload = malloc(1024);
			sprintf(payload,"/dh_data %s %s %s", tokens[2], tokens[3], logged_in[idx]);
			printf("%s\n", payload);
			send_to_user(payload,tokens[1]);
		}else if(!strcmp(tokens[0],"/write_group")) {
			int group_id;
			if(!tokens[1] || !(group_id=atoi(tokens[1]))) sprintf(output,"Invalid group id\n");
			else {
				char *broadcast_msg = malloc(1024);
				sprintf(broadcast_msg,"/g %s ",tokens[1]);
				for(int i=2;tokens[i];++i)
					sprintf(broadcast_msg,"%s %s",broadcast_msg,tokens[i]);
				sprintf(broadcast_msg,"%s\n", broadcast_msg);

				for(int i=1;i<42;++i) if(groups[i] && groups[i]->id == group_id){
					for(int j=0;j<42;++j) if(groups[i]->members[j] && groups[i]->members[j]!=idx) {
						send_to_user(broadcast_msg,logged_in[groups[i]->members[j]]);
					}
					sprintf(output,"Sent.\n");
					break;
				}
				if(strlen(output) == 0)
					sprintf(output,"No such group\n");
				free(broadcast_msg);
			}
			send_to_user(output,logged_in[idx]);
		} else if(!strcmp(tokens[0],"/request_public_key")) {
			sprintf(output,"Public key requested by: %s\n", logged_in[idx]);
			for(int i=1;tokens[i];++i) {
				if(send_to_user(output,tokens[i]))
					printf("Invalid user name: %s, skipping...\n",tokens[i]);
			}
		} else if(!strcmp(tokens[0],"/send_public_key")) {
			sprintf(output,"/pub_key %s %s", logged_in[idx], public_keys[idx]);
			printf("%s\n", output);
			for(int i=1;tokens[i];++i) {
				if(send_to_user(output,tokens[i]))
					printf("Invalid user name: %s, skipping...\n",tokens[i]);
				break;
			}
		} else if(!strcmp(tokens[0],"/list_user_files")) {
			if(!tokens[1] || !tokens[2]){
				sprintf(output, "Invalid parameter set\n");
				send_to_user(output,logged_in[idx]);
				continue;
			}
			sprintf(output,"Files:\n");
			if(!fork()){
				DIR *d = opendir(tokens[2]);
				struct dirent *dir;
				if(d){
					setuid(getpwnam(logged_in[idx])->pw_uid);
					while((dir=readdir(d))!=NULL){
						char *file_name = malloc(256);
						sprintf(file_name,"%s/%s", tokens[2],dir->d_name);
						struct stat sb; stat(file_name,&sb);
						if(!strcmp(tokens[1],getpwuid(sb.st_uid)->pw_name) && !access(file_name,R_OK))
							sprintf(output,"%s%s\n",output, file_name);
						free(file_name);
					}
					setuid(0);
					closedir(d);
				}
				send_to_user(output,logged_in[idx]);
				exit(0);
			} else{
				wait(NULL);
			}

		} else if(!strcmp(tokens[0],"/init_group_dhxchg")) {
			int gid = atoi(tokens[1]);
			sprintf(output,"/dh_user_list %d",gid);
			if(groups[gid])
				for(int i=0;i<42;++i) if(logged_in[groups[gid]->members[i]]!=0){
					sprintf(output,"%s %s",output, logged_in[groups[gid]->members[i]]);
				}
			printf("%s\n", output);
			send_to_user(output,logged_in[idx]);
		} else if(!strcmp(tokens[0],"/request_file")) {
			if(!tokens[1] || !tokens[2]){
				sprintf(output, "Invalid arguments.\n");
				send_to_user(output,logged_in[idx]);
				continue;
			} 

			if(!fork()){
				char *req = malloc(100);
				sprintf(req,"/req %s %s %s", tokens[1], tokens[2], logged_in[idx]);
				struct stat sb; 
				if(!stat(tokens[1],&sb)){
					setuid(getpwnam(logged_in[idx])->pw_uid);
					if(access(tokens[1],R_OK)){
						sprintf(output, "No read access.\n");
					} else if(send_to_user(req,getpwuid(sb.st_uid)->pw_name)){
						sprintf(output, "Owner not online...\n");
					} else {
						sprintf(output, "/ok\n");
					}
					setuid(0);
				} else {
					sprintf(output, "Invalid file name.\n");
				}
				send_to_user(output,logged_in[idx]);
				exit(0);
			} else {
				wait(NULL);
			}

		} else {
			sprintf(output,"Invalid command!\n");
			send_to_user(output,logged_in[idx]);
		}
		memset(message,0, sizeof message);
		free(output);
		free(tokens);
		fflush(stdout);
	}
	if(!received){
		printf("Client(# %d) disconnected\n", idx);
	} else if(received<0)
		printf("receive failed\n");

	clients[idx]=0;
	free(public_keys[idx]);
	logged_in[idx]=0;
	for(int i=0;i<4242;++i) if(groups[i]){
		for(int j=0;j<42;++j) if(groups[i]->members[j] == idx){
			groups[i]->members[j] = 0;
		}
	}
	return 0;
}

int get_free_index(){
	for(int i=1;i<MAX_CONNECTIONS;++i)
		if(!logged_in[i]) return i;
	return 0;
}

void *KDC(){
	int socket_desc , new_sock , c;
	struct sockaddr_in server , client;

	if((socket_desc=socket(AF_INET,SOCK_STREAM,0)) == -1){
		printf("Could not create socket");
		exit(1);
	}
	 
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(KDC_PORT);
	 
	if(bind(socket_desc,(struct sockaddr*)& server,sizeof(server))<0){
		printf("Bind failed\n");
		exit(1);
	}
	
	if(listen(socket_desc,3)<0){
		printf("Listen error");
		exit(1);
	}
	 
	puts("KDC Server initialized...");

	while(new_sock = accept(socket_desc,(struct sockaddr*)& client,(socklen_t*)& c)){

		char broadcast_msg[105], identity[105];
		
		memset(identity,0,sizeof identity);
		recv(new_sock,identity,105,0);

		sprintf(broadcast_msg, "KDC: New client(%s) connected\n", identity);
		// broadcast(broadcast_msg, idx);
		printf("%s", broadcast_msg);
		
		char salt[128], kdc_client[32], session_key[32];
		char *additional_payload = malloc(1024);

		for(int i=0;i<128;++i) salt[i] = 1;

		char *pass = malloc(105);
		sprintf(pass,"pw@%s",identity);

		for(int i=0;i<32;++i) session_key[i] = 1 + rand()%255;

		PKCS5_PBKDF2_HMAC_SHA1(pass,strlen(pass), salt, 128, 1, 32, kdc_client);

		char *payload = malloc(1024);
		for(int i=0;i<32;++i) payload[i] = session_key[i];
		for(int i=0;i<32;++i) additional_payload[i] = session_key[i];
		for(int i=0;i<strlen(identity);++i) additional_payload[32+i] = identity[i];
		enc(additional_payload,server_private_key,1);
		for(int i=0;i<512;++i) payload[512+i] = additional_payload[i];

		enc(payload,kdc_client,1);
		
		send(new_sock, payload, 1024, 0);
		// enc(payload,kdc_client,0);

		printf("KDC: Served client(%s)\n", identity);
		usleep(1000);
	}
}

int main(int argc , char *argv[]) {
	srand(0);
	// srand(time(NULL));
	pthread_t kdc;
	if(pthread_create(&kdc,NULL,KDC , NULL) < 0)
		return printf("Error while creating KDC thread\n"), 1;

	int socket_desc , new_sock , c;
	struct sockaddr_in server , client;

	if((socket_desc=socket(AF_INET,SOCK_STREAM,0)) == -1)
		return printf("Could not create socket"), 1;
	 
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(MAIN_PORT);
	 
	if(bind(socket_desc,(struct sockaddr*)& server,sizeof(server))<0)
		return printf("Bind failed\n"),1;
	
	if(listen(socket_desc,3)<0)
		return printf("Listen error"), 1;
	 
	puts("Server initialized...");
	
	int connected = 0;
	while(new_sock = accept(socket_desc,(struct sockaddr*)& client,(socklen_t*)& c)){
		++connected;

		char *payload=malloc(1024), *identity = malloc(1024), *personal_msg = malloc(1024), *broadcast_msg = malloc(1024);
		int idx = get_free_index();

		memset(identity,0,sizeof identity);
		memset(payload,0,sizeof payload);
		recv(new_sock,payload,512,0);

		enc(payload,server_private_key,0);

		for(int i=0;i<32;++i) identity[i] = payload[32+i];
		for(int i=0;i<32;++i) shared_secret[idx][i] = payload[i];

		public_keys[idx] = malloc(1024);
		recv(new_sock,public_keys[idx],1024,0); enc(public_keys[idx],shared_secret[idx],0);


		clients[idx] = new_sock;
		logged_in[idx] = malloc(105);
		strcpy(logged_in[idx], identity);
		
		sprintf(personal_msg, "You are connected to the server.\n");
		enc(personal_msg,shared_secret[idx],1);
		send(clients[idx], personal_msg, 1024, 0);

		sprintf(broadcast_msg, "New client(%s) connected\n", identity);
		printf("%s", broadcast_msg);
		// broadcast(broadcast_msg, idx);

		logged_in[idx] = (char *)malloc(105);
		strcpy(logged_in[idx], identity);

		pthread_t pthread;
		if(pthread_create(&pthread,NULL,manage_connection,(void*) &idx) < 0)
			return printf("Error while creating handling thread\n"), 1;
		usleep(1000);
	}
	
	close(socket_desc);
	return 0;
}