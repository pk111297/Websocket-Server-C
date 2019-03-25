#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<time.h>
#include "sha1.h"
#include "base64.h"
#define ntohs(n) (((((unsigned short)(n) & 0xFF))<<8) | (((unsigned short)(n) & 0xFF00)>>8))
#define FIN 128
#define FRAME_OPCODE_TEXT 1
#define FRAME_OPCODE_CLOSE 8
#define FRAME_OPCODE_PING 9
#define FRAME_OPCODE_PONG 10
#define HANSHAKE 100
#define MESSAGE_BUFFER_LENGTH 1024
#define MAX_CLIENTS 8
#define KEY_LENGTH 24
#define MESSAGE_LENGTH 36
#define KEY_MESSAGE_LENGTH (KEY_LENGTH + MESSAGE_LENGTH)
#define MAGIC_STRING "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define HANDSHAKE_REQ  "Sec-WebSocket-Key"
#define HANDSHAKE_ACCLEN 130
#define HANDSHAKE_ACCEPT                   \
"HTTP/1.1 101 Switching Protocols\r\n" \
"Upgrade: websocket\r\n"               \
"Connection: Upgrade\r\n"              \
"Sec-WebSocket-Accept: "               \

int file_descriptor[MAX_CLIENTS];
int connected_clients=0;
struct events
{
void (*onopen)(int);
void (*onclose)(int);
void (*onmessage)(int, unsigned char *);
void (*onerror)(char *);
};
int get_handshake_accept(char *,unsigned char **);
int get_handshake_response(char *,char **);
char* get_client_address(int);
int send_frame(int ,char *,int);
int create_socket(struct events *, int );
struct events events;
char* get_client_address(int fd)
{
struct sockaddr_in addr;
socklen_t addr_size;
char *client;
addr_size=sizeof(struct sockaddr_in);
if(getpeername(fd,(struct sockaddr *)&addr,&addr_size)<0) return NULL;
client=malloc(sizeof(char)*20);
strcpy(client,inet_ntoa(addr.sin_addr));
return client;
}
int * get_clients(int * abc)
{
abc=(int *)malloc(sizeof(file_descriptor));
int abcLength=sizeof(abc)/sizeof(int);
int n;
for(n=0;n<abcLength;++n)
{
abc[n]=file_descriptor[n];
}
return abc;
}
int get_handshake_accept(char *key,unsigned char **dest)
{
SHA1Context context;
char *str=malloc(sizeof(char)*(KEY_LENGTH+MESSAGE_LENGTH+1));
unsigned char hash[SHA1HashSize];
strcpy(str,key);
strcat(str,MAGIC_STRING);
SHA1Reset(&context);
SHA1Input(&context,(const uint8_t *)str,KEY_MESSAGE_LENGTH);
SHA1Result(&context,hash);
*dest=base64_encode(hash,SHA1HashSize, NULL);
*(*dest+strlen((const char *)*dest)-1)='\0';
free(str);
return 0;
}
int get_handshake_response(char *handshakeRequest, char **handshakeResponse)
{
char *s;
unsigned char *accept;
int t;
char *tt=(char*)malloc(strlen(handshakeRequest)+1);
strcpy(tt,handshakeRequest);
for(t=0,s=strtok(tt,"\r\n");s!=NULL;++t,s=strtok(NULL,"\r\n"))
{
if(t==0)
{
strcpy(tt,s);
//printf("(%s)\n",tt);
if(tt==NULL)
{
//printf("Invalid Header\n");
return -1;
}
if(strcmp("GET",strtok(tt," ")))
{
//printf("Invalid header GET\n");
return -1;
}
strtok(NULL," ");
if(strcmp("HTTP/1.1",strtok(NULL," "))>0)
{
//printf("Invalid header HTTP\n");
return -1;
}
s=strtok(handshakeRequest,"\r\n");
}
//printf("(%s)\n",s);
if(strstr(s,HANDSHAKE_REQ)!=NULL) break;
//printf("(%s)\n",s);
}
if(s==NULL)
{
//printf("Invalid header key\n");
return -1;
}
s=strtok(s," ");
s=strtok(NULL," ");
get_handshake_accept(s,&accept);
*handshakeResponse=malloc(sizeof(char)*HANDSHAKE_ACCLEN);
strcpy(*handshakeResponse,HANDSHAKE_ACCEPT);
strcat(*handshakeResponse,(const char *)accept);
strcat(*handshakeResponse,"\r\n\r\n");
free(accept);
free(tt);
return 0;
}
int send_frame(int fd,char *msg,int opcode_type)
{
unsigned char *response;
unsigned char frame[10];
uint8_t data_index;
uint64_t length;        
int response_index;      
int output;            
length=strlen((const char *)msg);
//printf("LENGTH%d,%s\n",length,msg);
if(opcode_type==FRAME_OPCODE_TEXT)
{
frame[0]=(FIN | opcode_type); //FRAME_OPCODE_TEXT
}
if(opcode_type==FRAME_OPCODE_PING)
{
frame[0]=(FIN | opcode_type);
}
if(opcode_type==FRAME_OPCODE_PONG)
{
frame[0]=(FIN | opcode_type); 
}
if(opcode_type==FRAME_OPCODE_CLOSE)
{
frame[0]=(FIN | opcode_type); 
}
if(length<=125)
{
frame[1]=length & 0x7F;
data_index=2;
}
else if(length>=126 && length<=65535)
{
frame[1]=126;
frame[2]=(length >> 8) & 255;
frame[3]=length & 255;
data_index=4;
}
else
{
frame[1]=127;
frame[2]=(unsigned char)((length >> 56) & 255);
frame[3]=(unsigned char)((length >> 48) & 255);
frame[4]=(unsigned char)((length >> 40) & 255);
frame[5]=(unsigned char)((length >> 32) & 255);
frame[6]=(unsigned char)((length >> 24) & 255);
frame[7]=(unsigned char)((length >> 16) & 255);
frame[8]=(unsigned char)((length >> 8) & 255);
frame[9]=(unsigned char)(length & 255);
data_index=10;
}
response_index=0;
response=malloc(sizeof(unsigned char)*(data_index+length +1));
for(int i=0;i<data_index;++i)
{
response[i]=frame[i];
++response_index;
}
for(int i=0;i<length;++i)
{
response[response_index]=msg[i];
++response_index;
}
response[response_index]='\0';
output=write(fd,response,response_index);
free(response);
return (output);
}
static unsigned char* receive_frame(unsigned char *frame, size_t length, int *type)
{
unsigned char *msg;
uint8_t mask;
uint8_t flength;
uint8_t idx_first_mask;
uint8_t idx_first_data;
size_t  data_length;
uint8_t masks[4];
int i,j;
msg=NULL;
//printf("FRAME:%s\n",frame);
//printf("BYTE:%d\n",frame[0]);
//printf("type:%d\n",frame[0]-128);
int opcode=frame[0]-128;
if(frame[0]==(FIN|FRAME_OPCODE_TEXT)||frame[0]==(FIN|FRAME_OPCODE_PONG)||frame[0]==(FIN|FRAME_OPCODE_PING) || frame[0]==(FIN|FRAME_OPCODE_CLOSE))
{
*type=opcode;
idx_first_mask=2;
mask=frame[1];
flength=mask & 0x7F;
if(flength==126) idx_first_mask=4;
else
{
if(flength==127) idx_first_mask=10;
}
idx_first_data=idx_first_mask+4;
data_length=length-idx_first_data;
masks[0]=frame[idx_first_mask+0];
masks[1]=frame[idx_first_mask+1];
masks[2]=frame[idx_first_mask+2];
masks[3]=frame[idx_first_mask+3];
msg=malloc(sizeof(unsigned char)*(data_length+1));
for(i=idx_first_data,j=0;i<length;++i,++j)  msg[j]=frame[i]^masks[j%4];
msg[j]='\0';
//printf("data_length:%d\tmsg:%s\n",data_length,msg);
if(opcode==FRAME_OPCODE_TEXT)
{
//printf("receive text frame\n");
return msg;
}
if(opcode==FRAME_OPCODE_PING)
{
//printf("send pong frame\n");
return msg;
}
if(opcode==FRAME_OPCODE_PONG)
{
//printf("receive pong frame\n");
return msg;
}
if(opcode==FRAME_OPCODE_CLOSE)
{
unsigned short sz16;
memcpy(&sz16,msg,sizeof(unsigned short));
//printf("ntohs:%d\n",ntohs(sz16));
//printf("receive close frame\n");
return msg;
}
}
else 
{
*type=HANSHAKE;
//printf("UNSUPPORTED/HANDSHAKE   FRAME CODE:%d\n\t msg:%s",opcode,msg);
return msg;
}
//printf("hhihihihihuisdhfi\n");
}
static void* ws_establishconnection(void *vsock)
{
//printf("forehead of ws_estt\n");
int sock;
size_t n;                           
unsigned char frm[MESSAGE_BUFFER_LENGTH];  
unsigned char *msg;                 
char *response;
int  handshaked; 
int  type;
handshaked = 0;
int close_frame_signal=0;
sock=(int)(intptr_t)vsock;
while((n=read(sock,frm,sizeof(unsigned char)*MESSAGE_BUFFER_LENGTH))>0)
{
//printf("forehead looooop of ws_estt%d\n",handshaked);
if(close_frame_signal) break;
if(!handshaked)
{
int result=get_handshake_response((char *)frm,&response);
if(result==-1)
{
sprintf(response,"%d Bad Request",404);
n=write(sock, response, strlen(response));
events.onerror("Invalid Header");
close(sock);
break;
}
if(get_client_address(sock)==NULL) break;
handshaked=1;
n=write(sock, response, strlen(response));
file_descriptor[connected_clients++]=sock;
printf("Client Connected with File Descriptor as:%d,and ip as:%s\n",sock,get_client_address(sock));
events.onopen(sock);
free(response);
}
msg=receive_frame(frm,n,&type);
if(type==FRAME_OPCODE_TEXT)
{
events.onmessage(sock,msg);
free(msg);
}
else 
{
if(type==FRAME_OPCODE_CLOSE)
{
close_frame_signal=1;
handshaked=0;
int result=send_frame(sock,msg,FRAME_OPCODE_CLOSE);
//printf("pp:%d\t",result);
printf("Client Closed with File Descriptor as:%d,and ip as:%s\n",sock,get_client_address(sock));
events.onclose(sock);
result=close(sock);
//printf("close Sock Called:%d\n",result);
//printf("Client Connected with File Descriptor as:%d,and ip as:%s\n",sock,get_client_address(sock));
int k;
for(k=0;k<connected_clients;++k)
{
if(file_descriptor[k]==sock)
{
int j;
for(j=k;j<connected_clients;++j) file_descriptor[j]=file_descriptor[j+1];
--connected_clients;
break;
}
}
free(msg);
}
else
{
if(type==FRAME_OPCODE_PING)
{
//printf("PING frame type\n");
int result=send_frame(sock,msg,FRAME_OPCODE_PONG);
//printf("pp:%d\t",result);
free(msg);
}
else
{
if(type==FRAME_OPCODE_PONG)
{
//printf("PONG frame type\n");
file_descriptor[connected_clients++]=sock;
free(msg);
}
else
{
//printf("Unsupported frame type\n");
}
}
}
}
}
return vsock;
}
void * send_ping_frame()
{
while(1)
{
//printf("ping frame sending....\n");
for(int i=0;i<connected_clients;++i)
{
int result=send_frame(file_descriptor[i],"this is ping frame",FRAME_OPCODE_PING);
//printf("pp:%d\t",result);
}
connected_clients=0;
sleep(30);
}
}
int create_socket(struct events *evs, int port)
{
int sock;
int new_socket; 
struct sockaddr_in server;
struct sockaddr_in client;
int len;
if(evs==NULL)
{
perror("Error:An error has ocurred, please review your events\n");
return -1;
}
if(port<=0||port> 65535)
{
printf("Error:Cannot listen at port:%d, please give a valid port number(0-65535)!\n",port);
return -1;
}
memcpy(&events,evs,sizeof(struct events));
sock=socket(AF_INET, SOCK_STREAM,0);
if(sock<0)
{
perror("Error:An error has ocurred, Could not create socket\n");
return -1;
}
if(setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&(int){1},sizeof(int))<0)
{
perror("Error:An error has ocurred, setsockopt(SO_REUSEADDR) failed\n");
return -1;
}
server.sin_family = AF_INET;
server.sin_addr.s_addr = INADDR_ANY;
server.sin_port = htons(port);
if(bind(sock,(struct sockaddr *)&server,sizeof(server))<0) 
{
perror("Error:An error has ocurred, Binding failed\n");
return -1;
}
listen(sock,MAX_CLIENTS);
time_t t;
time(&t);
char *timedate=ctime(&t);
timedate[strlen(timedate)-1]='\0';
printf("%s:Websocket server started and ready to accept connection on port %d\n",timedate,port);
len=sizeof(struct sockaddr_in);
pthread_t ping_thread;
if(pthread_create(&ping_thread,NULL,send_ping_frame,NULL)<0)
{
perror("Error:An error has ocurred,Could not create the Ping thread\n");
return -1;
}
pthread_detach(ping_thread);
while (1)
{
new_socket=accept(sock,(struct sockaddr *)&client,(socklen_t*)&len);
if(new_socket<0)
{
perror("Error:An error has ocurred, Error on accepting conections..\n");
//exit(-1);
return -1;
}
pthread_t client_thread;
if(pthread_create(&client_thread,NULL,ws_establishconnection,(void*)(intptr_t)new_socket)<0)
{
perror("Error:An error has ocurred,Could not create the Client thread\n");
return -1;
}
pthread_detach(client_thread);
}
}
