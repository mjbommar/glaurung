#include "runtime_sample.h"
#include <arpa/inet.h>
#include <sys/socket.h>
int main(int argc,char **argv){int s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=0;a.sin_addr.s_addr=htonl(rs_bad(argc,argv)?INADDR_ANY:INADDR_LOOPBACK);int r=bind(s,(struct sockaddr *)&a,sizeof a);rs_checkpoint();close(s);return rs_result("bind",r);}
