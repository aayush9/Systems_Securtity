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
#include <assert.h>

const int PORT=4257;
int clients[4242];
int groups[4242] = {0,1,1,3};
char *logged_in[4242], *current_directory[4242], ROOT_DIR[205], CURRENT_DIR[]="__current";

int goto_directory(char path[], int index){
	chdir(current_directory[index]);
	if(!path || !path[0]) return 0;
	for(int i=1;path[i];++i) if(path[i]=='/'&&path[i-1]=='/') return 1;
	if(path[0] == '/') chdir(ROOT_DIR), ++path;
	for(char *token,*s=path;token=strtok_r(s,"/",&s);){
		if(chdir(token)) return -1;
		char pwd[505]; getcwd(pwd,505); strcat(pwd,"/");
		for(int i=0;ROOT_DIR[i];++i) if(pwd[i]!=ROOT_DIR[i]) return 1;
	}
	return 0;
}

int get_uid_gid(char fname[], int *uid, int *gid){
	*uid = *gid = 0;
	char path[305] = ".";
	strcat(path,fname);
	FILE *file = fopen(path,"r");
	if(!file) return 0;
	char line[105];
	fgets(line, 105,file); *uid = atoi(line);
	fgets(line, 105,file); *gid = atoi(line);
	fclose(file);
	return 1;
}
char *get_last_token(char *path){
	char *file_name = (char*) malloc(105);
	int last_slash=0;
	for(int i=0;path[i];++i) if(path[i]=='/') last_slash = i+1;
	strcpy(file_name,path+last_slash);
	for(int i=last_slash;path[i];path[i++]=0);
	return file_name;
}

char* cd(int index, char* args[]){
	char *output = (char *) malloc(10005);
	if(!args[1]){
		args[1] = (char*) malloc(1005);
		sprintf(args[1],"/simple_home/%s/",logged_in[index]);
	}
	int status = goto_directory(args[1],index);
	if(status==1) return sprintf(output,"Invalid directory path...\n"), output;
	else if(status==-1) return sprintf(output,"%s: No such directory\n", args[1]), output;
	memset(current_directory[index],0,1005);
	getcwd(current_directory[index],405);
	strcat(current_directory[index],"/");
	return output;
}

char* ls(int index, char* args[]){
	char *output = (char *) malloc(10005);
	struct dirent *ptr;
	DIR *dir;
	if(args[1]){
		int status = goto_directory(args[1],index);
		if(status==1) return sprintf(output,"Invalid directory path...\n"), output;
		else if(status==-1) return sprintf(output,"%s: No such directory\n", args[1]), output;
	}
	else chdir(current_directory[index]);
	if(!(dir = opendir("."))) return sprintf(output,"Invalid directory path...\n"), output;
	for (int i=0;(ptr=readdir(dir));++i){
		if(ptr->d_name[0]=='.') continue;
		struct stat fs; stat(ptr->d_name,&fs);
		int uid,gid;
		if(S_ISREG(fs.st_mode)) get_uid_gid(ptr->d_name,&uid,&gid);
		else{
			chdir(ptr->d_name);
			get_uid_gid(CURRENT_DIR,&uid,&gid);
			chdir("..");
		}
		sprintf(output,"%s%s   UID: %d   GID: %d\n",output,ptr->d_name, uid,gid);
	}
	closedir(dir);
	return output;
}

char* fput(int index, char* args[]){
	char *output = (char *) malloc(10005);
	if(!args[1]) return sprintf(output,"No argument...\n"), output;
	if(args[1][strlen(args[1])-1]=='/') return sprintf(output,"Path given is a directory...\n"), output;

	char *file_name = get_last_token(args[1]);
	int status = goto_directory(args[1],index);
	if(status==1) return sprintf(output,"Invalid directory path...\n"), output;
	else if(status==-1) return sprintf(output,"%s: No such directory\n", args[1]), output;

	struct stat filestat;
	if(!stat(file_name,&filestat) && !S_ISREG(filestat.st_mode)) return sprintf(output,"It's a directory...\n"), output;
	
	char *auxiliary = (char*)malloc(305);
	sprintf(auxiliary,".%s",file_name);

	int uid,gid;
	if(stat(file_name,&filestat)){
		struct stat parent_st;
		char *pwd = (char*) malloc(505); getcwd(pwd,505);
		get_uid_gid(CURRENT_DIR,&uid,&gid);
		if(uid!=index) return sprintf(output,"Not owner of parent directory, no write permissions\n"), output;
		char message[205],ask_uid[205] = "Enter owner id: ", ask_gid[205] = "Enter group id: ";
		int uid_len = strlen(ask_uid), gid_len = strlen(ask_gid);

		uid = gid = 0;
		do{
			send(clients[index],ask_uid,uid_len,0);
			recv(clients[index],message,205,0);
			uid = atoi(message);
		} while(!uid);

		do{
			send(clients[index],ask_gid,gid_len,0);
			recv(clients[index],message,205,0);
			gid = atoi(message);
		} while(!gid);

		FILE *file = fopen(file_name,"w");
		fclose(file);
		file = fopen(auxiliary,"w");
		fprintf(file, "%d\n%d\n", uid,gid);
		fclose(file);
	}
	get_uid_gid(file_name,&uid,&gid);
	if(uid!=index) return sprintf(output,"You are not the owner, write not allowed...\n"), output;
	FILE *file = fopen(file_name,"a");
	char *message = (char*) malloc(205),prompt[205] = ": ";
	int prompt_len = strlen(prompt);
	send(clients[index],prompt,prompt_len,0);
	recv(clients[index],message,205,0);
	fprintf(file,"%s\n",message);
	fclose(file);
	return output;
}

char* fget(int index, char* args[]){
	char *output = (char *) malloc(10005);
	if(!args[1]) return sprintf(output,"No argument...\n"), output;
	if(args[1][strlen(args[1])-1]=='/') return sprintf(output,"Path given is a directory...\n"), output;

	char *file_name = get_last_token(args[1]);
	int status = goto_directory(args[1],index);
	if(status==1) return sprintf(output,"Invalid directory path...\n"), output;
	else if(status==-1) return sprintf(output,"%s: No such directory\n", args[1]), output;

	struct stat filestat;
	if(!stat(file_name,&filestat) && S_ISREG(filestat.st_mode)){
		int uid,gid;
		get_uid_gid(file_name,&uid,&gid);
		if(uid!=index && gid!=groups[index]) return sprintf(output,"Not owner or group, read not allowed...\n"), output;
		FILE *file = fopen(file_name,"r");
		for(char line[205];fgets(line,sizeof line, file);sprintf(output,"%s%s",output,line));
		fclose(file);
	}
	else if(!S_ISREG(filestat.st_mode)) sprintf(output,"It's a directory...\n");
	else sprintf(output,"File doesn't exist...\n");
	return output;
}

char* create_dir(int index, char* args[]){
	char *output = (char *) malloc(10005);
	if(!args[1]) return sprintf(output,"No argument...\n"),output;
	if(args[1][strlen(args[1])-1]=='/') args[1][strlen(args[1])-1]=0;
	if(args[1][strlen(args[1])-1]=='/') return sprintf(output,"Invalid directory path...\n"), output;

	char *dir_name = get_last_token(args[1]);

	int status = goto_directory(args[1],index);
	if(status==1) return sprintf(output,"Invalid directory path...\n"), output;
	else if(status==-1) return sprintf(output,"%s: No such parent directory\n", args[1]), output;

	struct stat st,parent_st;
	int uid,gid; get_uid_gid(CURRENT_DIR,&uid,&gid);
	if(uid!=index) return sprintf(output,"Not owner, no write permissions\n"), output;
	if(!stat(dir_name,&st)) return sprintf(output,"Directory exists\n"), output;
	mkdir(dir_name,0777);
	char new_dir[305]; getcwd(new_dir,305); sprintf(new_dir,"%s/%s/.__current",new_dir,dir_name);
	FILE *file = fopen(new_dir,"w");
	fprintf(file, "%d\n%d\n", uid,gid);
	fclose(file);
	return output;
}

void *manage_connection(void* index) {
	int idx = *((int *)index), received,oput_len;

	printf("Logged in: %s\n", logged_in[idx]);
	current_directory[idx] = (char *) malloc(1005);
	sprintf(current_directory[idx],"%ssimple_home/%s/",ROOT_DIR,logged_in[idx]);

	struct stat st;
	if(stat(current_directory[idx],&st)==-1) mkdir(current_directory[idx],0700);
	char *new_dir = (char*) malloc(305); sprintf(new_dir,"%s/.__current",current_directory[idx]);
	
	FILE *file = fopen(new_dir,"w"); fprintf(file, "%d\n%d\n", idx,idx); fclose(file);
	
	char *output; output = (char*) malloc(10005);
	sprintf(output,"%s$ ",current_directory[idx]+strlen(ROOT_DIR)-1);
	send(clients[idx],output,oput_len=strlen(output),0);
	
	for(char message[1005];(received = recv(clients[idx],message,1005,0))>0;memset(message,0,sizeof message)){
		if(!strcmp(message,"logout") || !strcmp(message,"exit")){
			received = 0; break;
		}
		char *word = strtok(message," "), *args[105];
		for(int len=0;word!=NULL;++len){
			args[len] = (char*) malloc(strlen(word));
			strcpy(args[len],word);
			args[len+1] = NULL;
			word = strtok(NULL," ");
		}
		output = (char*) malloc(10005);
		if(!strcmp(args[0],"create_dir")) output = create_dir(idx, args);
		else if(!strcmp(args[0],"fput")) output = fput(idx, args);
		else if(!strcmp(args[0],"fget")) output = fget(idx, args);
		else if(!strcmp(args[0],"ls")) output = ls(idx, args);
		else if(!strcmp(args[0],"cd")) output = cd(idx, args);
		else  sprintf(output,"Unknown command...\n");
		sprintf(output,"%s%s$ ",output,current_directory[idx]+strlen(ROOT_DIR)-1);
		send(clients[idx],output,oput_len=strlen(output),0);
	}
	if(!received) printf("Client(# %d) disconnected\n", idx);
	else if(received<0) printf("receive failed\n");
	clients[idx] = 0; logged_in[idx] = 0;
	return 0;
}

int check(char identity[]){
	if(!identity || identity[0] != 'u') return 0;
	int i = atoi(identity+1);
	if(!i || logged_in[i]) return 0;
	logged_in[i] = (char*) malloc(strlen(identity)+5);
	sprintf(logged_in[i],"%s",identity);
	return i;
}

int main(int argc, char *argv[]) {
	getcwd(ROOT_DIR, 205); strcat(ROOT_DIR,"/simple_slash/");
	mkdir("simple_slash",0777); mkdir("simple_slash/simple_home",0777);
	int socket_desc , new_sock , c;
	struct sockaddr_in server , client;
	if((socket_desc=socket(AF_INET,SOCK_STREAM,0)) == -1) return printf("Could not create socket"), 1;
	server.sin_family = AF_INET, server.sin_addr.s_addr = INADDR_ANY, server.sin_port = htons(PORT);
	if(bind(socket_desc,(struct sockaddr*)& server,sizeof(server))<0) return printf("Bind failed\n"),1;
	if(listen(socket_desc,3)<0) return printf("Listen error"), 1;

	while(new_sock = accept(socket_desc,(struct sockaddr*)& client,(socklen_t*)& c)){
		char identity[105];
		int received = recv(new_sock,identity,1005,0), index;
		if(!(index = check(identity))){
			char msg[] = "Invalid credentials...\n";
			int len = strlen(msg);
			send(new_sock,msg,len, 0);
			usleep(200);
			continue;
		}
		clients[index] = new_sock;
		pthread_t pthread;
		if(pthread_create(&pthread,NULL,manage_connection , (void*) &index) < 0)
			return printf("Error while creating handling thread\n"), 1;
	}
	close(socket_desc);
	return 0;
}