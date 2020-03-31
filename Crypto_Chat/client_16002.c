#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "crypt.c"

const long long md = 1000000007, g = 3;
long long power(long long a,long long p){
	return p?power(a*a%md,p/2)*(p&1?a:1)%md:1;
}

char shared_secret[32];
char *pri_key, *pub_key;

char *logged_in[4242];
char *public_keys[4242];

int conn, kdc_conn;

long long  exponent;
char dh[4242][32];
int lookup(char name[]){
	for(int i=0;i<4242;++i) if(!strcmp(name,logged_in[i]))
		return i;
	return 0;
}
void* send_messages(){
	unsigned char input[1024];
	while(fgets(input,1024,stdin)){
		if(input[0] == '\n') continue;
		input[strlen(input)-1] = 0;
		if(!strcmp(input,"/quit")) exit(0);
		char **tokens = tokenize(input);
		if(!strcmp(tokens[0],"/write_group")){
			int gid = atoi(tokens[1]);
			char *payload = malloc(1024);
			for(int i=2;tokens[i];++i)
				sprintf(payload,"%s %s", payload, tokens[i]);
			enc(payload, dh[gid], 1);
			
			memset(input,0,sizeof input);
			sprintf(input, "%s %s %s", tokens[0], tokens[1], payload);
		}
		enc(input,shared_secret,1);
		if(send(conn, input,1024,0)<0){
			printf("Can't send message, server disconnected, exiting\n");
			exit(0);
		}
		if(!strcmp(tokens[0],"/request_file")){
			int socket_desc , new_sock , c;
			struct sockaddr_in server , client;
			if((socket_desc=socket(AF_INET,SOCK_STREAM,0)) == -1){
				printf("Could not create socket");
				continue;
			}
			 
			server.sin_family = AF_INET;
			server.sin_addr.s_addr = INADDR_ANY;
			server.sin_port = htons(atoi(tokens[2]));
			 
			if(bind(socket_desc,(struct sockaddr*)& server,sizeof(server))<0){
				printf("Bind failed\n");
				continue;
			}
			
			if(listen(socket_desc,3)<0){
				printf("Listen error");
				continue;
			}
			 
			puts("Listening for file...\n");
			new_sock = accept(socket_desc,(struct sockaddr*)& client,(socklen_t*)& c);
			char *payload=malloc(1024);
			sprintf(payload,"/hello");
			// for(int i=0;i<10;++i) printf("%d ", payload[i]); puts("\n\n");
			sign(payload,pri_key,1);
			// for(int i=0;i<10;++i) printf("%d ", payload[i]); puts("\n\n");
			send(new_sock,payload,1024,0);
			printf("Sent Certificate\n");
			memset(payload,0,sizeof payload);
			
			recv(new_sock,payload,1024,0);
			// enc_asymmetric(payload,pri_key,0);

			FILE *file = fopen("new_file.txt","w");
			fprintf(file,"%s\n",payload);
			fclose(file);

			close(socket_desc);
		}

		memset(input,0, sizeof input);
	}
}

void* receive_messages(){
	unsigned char output[1024];
	for(;;fflush(stdout)){
		memset(output,0, sizeof output);
		if(recv(conn,output,1024,0)<=0){
			printf("Can't receive message, server disconnected, exiting\n");
			exit(0);
		}
		enc(output, shared_secret,0);

		char **tokens = tokenize(output);
		if(!strcmp(tokens[0],"/pub_key")){
			for(int i=0;i<4242;++i) if(logged_in[i] == NULL){
				logged_in[i] = malloc(1024);
				public_keys[i] = malloc(1024);
				strcpy(logged_in[i], tokens[1]);
				strcpy(public_keys[i],output+10+strlen(tokens[1]));
				break;
			}
			continue;
		}
		if(!strcmp(tokens[0],"/g")){
			int gid = atoi(tokens[1]);
			char *payload = malloc(1024);
			strcpy(payload,tokens[2]);
			enc(payload, dh[gid], 0);
			for(int i=0;i<strlen(payload);++i) if(payload[i]=='\n') payload[i]=0;
			printf("Group %d: %s\n", gid, payload);
			continue;
		}
		printf("%s",output);
		if(!strcmp(tokens[0],"/req")){
			usleep(100000);
			int to_serve=-1;
			for(to_serve=0;to_serve<4242;++to_serve) if(logged_in[to_serve]){
				if(!strcmp(tokens[3],logged_in[to_serve])) break;
			}
			if(to_serve==-1){
				printf("\nDon't have public key of requester\n");
				continue;
			}
			if(!public_keys[to_serve]){
				printf("\nDon't have guy's public key.\n");
				continue;
			}
			printf("%s\n", public_keys[to_serve]);
			struct sockaddr_in server;
			int conn;
			if ((conn=socket(AF_INET,SOCK_STREAM,0)) == -1){
				printf("Could not create socket\n");
				continue;
			}

			server.sin_addr.s_addr = inet_addr("127.0.0.1");
			server.sin_family = AF_INET;
			server.sin_port = htons(atoi(tokens[2]));
			if (connect(conn,(struct sockaddr *)&server , sizeof(server)) < 0){
				printf("Connect failed. Error\n");
				continue;
			}
			recv(conn,output,1024,0);
			// for(int i=0;i<10;++i) printf("%d ", output[i]); puts("\n\n");
			sign(output,public_keys[to_serve],0);
			// for(int i=0;i<10;++i) printf("%d ", output[i]); puts("\n\n");
			if(strcmp(output,"/hello")){
				printf("Certificate can't be verified.\n");
				continue;
			}
			printf("\nCertificate verified...\nSending...\n");
			char *payload = malloc(1024);
			FILE *file = fopen(tokens[1],"r");
			for(char line[205];fgets(line,205,file); sprintf(payload,"%s%s",payload, line));
			fclose(file);
			// enc_asymmetric(payload,public_keys[to_serve],1);
			send(conn,payload,1024,0);
			close(conn);
			printf("Sent\n");
		}
		if(!strcmp(tokens[0],"/dh_user_list")){
			long long key = power(g,exponent);
			for(int i=2;tokens[i];++i) if(strcmp(tokens[i],getpwuid(getuid())->pw_name)){
				if(public_keys[lookup(tokens[i])]==NULL){
					printf("lol\n");
					break;
				}

				char *payload = malloc(1024);
				char *dh_exp = malloc(1024);
				sprintf(dh_exp,"%lld", key);
				// enc_asymmetric(dh_exp,public_keys[lookup(tokens[i])],1);
				sprintf(payload,"/write_user %s %s %s", tokens[i], tokens[1], dh_exp);
				
				enc(payload,shared_secret,1);
				send(conn,payload,1024,0);
				
				memset(payload,0,sizeof payload);
				recv(conn, payload, 1024, 0);
				enc(payload, shared_secret,0);

				char **toks = tokenize(payload);
				long long key_new = atoi(toks[2]) ^ key;
				
				int gid = atoi(toks[1]);
				memset(dh[gid],0,sizeof dh[gid]);
				sprintf(dh[gid],"%lld", key_new);
				printf("\nDH Key:%s\n", dh[gid]);
				key = key_new;
				// break;
			}	
		}
		if(!strcmp(tokens[0],"/dh_data")){
			char *payload = malloc(1024);
			int gid = atoi(tokens[1]);
			strcpy(payload,tokens[2]);
			// enc_asymmetric(payload,pri_key,0);
			long long key = atoi(payload);
			long long key_new = power(key,exponent);
			char *key_s = malloc(1024);
			sprintf(key_s,"%lld", key_new);
			strcpy(dh[gid],key_s);

			sprintf(payload,"/write_user %s %d %lld", tokens[3], gid, key^key_new);

			enc(payload,shared_secret,1);
			send(conn,payload,1024,0);

			printf("\nDH Key:%s\n", dh[gid]);
		}
	}
}
int main(int argc, char *argv[]) {
	if(argc<2) return printf("Enter server's IP as CLI argument\n"), 0;

	memset(dh,0,sizeof dh);
	srand(time(NULL));
	memset(dh,0,sizeof dh);
	exponent = rand();
	// Reference: https://shanetully.com/2012/04/simple-public-key-encryption-with-rsa-and-openssl/
	RSA *keypair = RSA_generate_key(512, 3, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem()), *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	size_t pri_len = BIO_pending(pri), pub_len = BIO_pending(pub);

	pri_key = malloc(pri_len + 1); pub_key = malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// printf("\n%s\n%s\n", pri_key, pub_key);

	// char test[1024] = "This is a test.";
	// sign(test,pri_key,1);
	// printf("%s\n", test);
	// sign(test,pub_key,0);
	// printf("%s\n", test);
	// return 0;

	struct sockaddr_in server;
	char message[1000] , server_reply[2000];
	 
	if ((kdc_conn=socket(AF_INET,SOCK_STREAM,0)) == -1)
		return printf("Could not create socket"), 1;
	 
	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_family = AF_INET;
	server.sin_port = htons(KDC_PORT);
 
	if (connect(kdc_conn,(struct sockaddr *)&server,sizeof(server)) < 0)
		return printf("connect failed. Error"), 1;

	char *msg = malloc(32);
	char *payload = malloc(1024);
	memset(msg,0,sizeof msg);
	struct passwd *pws = getpwuid(getuid());
	strcpy(msg,pws->pw_name);
	send(kdc_conn, msg, 32,0);

	char *pass = malloc(105);
	sprintf(pass,"pw@%s",pws->pw_name);

	char salt[128]; for(int i=0;i<128;++i) salt[i] = 1;

	char *kdc_key = malloc(32);
	PKCS5_PBKDF2_HMAC_SHA1(pass, strlen(pass), salt, 128, 1, 32, kdc_key);
	recv(kdc_conn,payload,1024,0);

	enc(payload,kdc_key,0);

	for(int i=0;i<32;++i) shared_secret[i] = payload[i];	

	if ((conn=socket(AF_INET,SOCK_STREAM,0)) == -1)
		return printf("Could not create socket"), 1;

	server.sin_addr.s_addr = inet_addr(argv[1]);
	server.sin_family = AF_INET;
	server.sin_port = htons(MAIN_PORT);

	if (connect(conn,(struct sockaddr *)&server , sizeof(server)) < 0)
		return printf("connect failed. Error"), 1;

	send(conn,payload+512, 512,0);

	memset(payload,0,sizeof payload);
	for(int i=0;i<strlen(pub_key);++i) payload[i] = pub_key[i];
	enc(payload,shared_secret,1);
	send(conn, payload, 1024,0);

	pthread_t r,s;
	if(pthread_create(&r,NULL,receive_messages,NULL)<0 || pthread_create(&s,NULL,send_messages,NULL)<0)
			return printf("Error while creating threads\n"), 1;

	pthread_join(r,NULL);
	pthread_join(s,NULL);
	 
	close(conn);
	return 0;
}