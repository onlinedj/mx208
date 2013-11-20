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
        while(1) 
        {
            uint32_t info[4] = {1,counter*10,counter*20,counter*30};
            
            int result = send(sockfd, info, sizeof(uint32_t)*4,0); 
            printf("%d send result=%d,errno=%d\n",counter,result,errno);
            while(1)
            {
                uint32_t header[4] = {0,0,0,0};
                memset(header,'0',sizeof(uint32_t)*4);
                int n = recv(sockfd,header,sizeof(uint32_t)*4,0); 
                printf("recv success!%d,%d,%d,%d\n",header[0],header[1],header[2],header[3]);
                break;
                /*if(n>0)
                {
                    int * data;          
                    int m = recv(sockfd,data,header[1],0);
                    if(m>0)
                    {
                    }
                }*/
            }
            sleep(5);
        }
    }

    /*while (1)
    {
        n = recv(sockfd, recvBuff, sizeof(recvBuff)-1,0);
        recvBuff[n] = 0;
        if(fputs(recvBuff, stdout) == EOF)
        {
            printf("endof receive buff\n");
        }
        if(n < 0)
        {
            sleep(1);
        } 
    } */

    return 0;
}
