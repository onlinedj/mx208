#include "mxserver.h"

#include <pthread.h> //for multi-threaded arch
#include <stdio.h> //for print log
#include <sys/socket.h>//for socket listen/bind
#include <stdio.h>//for printf
#include <errno.h>//for get err no.
#include <arpa/inet.h>//for inet macros
#include <sys/types.h>//for legency dependency
#include <string.h>//for memset
#include <unistd.h>
#include <fcntl.h> //for setting non-blocking

#include "connection_handler.h"
#include "command_handler.h"

uint32_t get_ip(IFACE eth)
{
    return 0;
}

int create_server_socket(uint32_t ip, uint32_t port)
{
    int listen_fd = 0;
    struct sockaddr_in serv_addr; 
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(-1 == listen_fd) 
    {
        return CREATE_SOCKET_FAILED; 
    }
//TODO here we wanna have reactor model to get high performance.
//    fcntl(listen_fd, F_SETFL,fcntl(listen_fd, F_GETFL) | O_NONBLOCK);

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(ip);
    serv_addr.sin_port = htons(port); 

    if(bind(listen_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)))
    {
        return CREATE_SOCKET_FAILED; 
    }

    if(listen(listen_fd, 10))
    {
        return CREATE_SOCKET_FAILED; 
    }
    return listen_fd;

}



int main(int argc, char *argv[])
{
    int eth0_fd = 0, eth1_fd = 0; 
    long conn0_fd = 0, conn1_fd = 0;

    init_queues();
    printf("init queue ok\n");
    start_command_threads();
    printf("init command threads ok\n");

    //init connection handler.
    //TODO use get_ip instead in future.
    eth0_fd = create_server_socket(INADDR_ANY,SOCKET_PORT_NORMAL);
    eth1_fd = create_server_socket(INADDR_ANY,SOCKET_PORT_MANAGE);
    
    while(1)
    {
        //TODO here we wanna have reactor model to get high performance.
        conn0_fd = accept(eth0_fd, (struct sockaddr*)NULL, NULL); 
        if(conn0_fd>0)
        {
            pthread_t tid;
            pthread_create(&tid, NULL, handle_connection, (void*) conn0_fd);
            printf("create connection thread ok\n");
        }
        conn1_fd = accept(eth1_fd, (struct sockaddr*)NULL, NULL); 
        if(conn1_fd>0)
        {
            pthread_t tid;
            pthread_create(&tid, NULL, handle_connection, (void*) conn1_fd);
        }
    }

}
