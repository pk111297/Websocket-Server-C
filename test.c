#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "websocket.h"
void onopen(int fd)
{
char *cli;
cli = get_client_address(fd);
printf("Connection opened, client: %d | addr: %s\n", fd, cli);
free(cli);
}
void onclose(int fd)
{
char *cli;
cli = get_client_address(fd);
printf("Connection closed, client: %d | addr: %s\n", fd, cli);
free(cli);
}
void onerror(char *error)
{
printf("Error: %s\n",error);
}
void onmessage(int fd, unsigned char *msg)
{
char *cli;
cli = get_client_address(fd);
printf("Received message: %s, from: %s/%d\n", msg, cli, fd);
sleep(2);
send_frame(fd, "Hello Bhai",FRAME_OPCODE_TEXT);
free(cli);
}
int main()
{
struct events evs;
evs.onopen=&onopen;
evs.onclose=&onclose;
evs.onmessage=&onmessage;
create_socket(&evs,10000);
return 0;
}
