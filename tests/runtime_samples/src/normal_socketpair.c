#include "runtime_sample.h"
#include <sys/socket.h>
int main(int argc,char **argv){(void)argc;(void)argv;int s[2];char c=0;if(socketpair(AF_UNIX,SOCK_STREAM,0,s))return 2;send(s[0],"S",1,0);recv(s[1],&c,1,0);close(s[0]);close(s[1]);return rs_result("socketpair",c);}
