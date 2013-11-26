#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <pthread.h>

void *send_info(void *arg)
{
    return NULL;
}

int main(int argc, char *argv[])
{
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr; 
    int counter = 0;

    if(argc != 2)
    {
        printf("\n Usage: %s <ip of server> \n",argv[0]);
        return 1;
    } 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Error : Could not create socket \n");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8990); 

    if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr)<=0)
    {
        printf("\n inet_pton error occured\n");
        return 1;
    } 

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       printf("\n Error : Connect Failed \n");
       return 1;
    } else {
        /*int i;
        for(i=0;i<5;i++)
        {
            pthread_t tid;
            pthread_create(&tid,NULL,send_info,NULL);
        }*/
        uint8_t buffer[65536];
        while(1) 
        {
            uint32_t info[4] = {1,counter*10,counter*20,counter*30};
            int result = send(sockfd, info, sizeof(uint32_t)*4,0); 
            printf("%d send result=%d,errno=%d\n",sockfd,result,errno);
            memset(buffer,0,65536);
            while(1)
            {
                uint32_t *tmp = (uint32_t *)buffer;
                int n = recv(sockfd,buffer,65536,0); 
                printf("recv success!recev=%d;header:%u,%u,%u,%u;\n",n,tmp[0],tmp[1],tmp[2],tmp[3]);
                break;
            }
            usleep(2000);
        }
    }

    return 0;
}

