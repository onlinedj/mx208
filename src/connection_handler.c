#include "connection_handler.h"

#include <stdint.h>
#include <sys/socket.h>
#include <string.h>

#include "queue.h"
#include "command_handler.h"

#define DEBUG_CONN 1
#define REQUEST_DEVICE_INFO 1

void *handle_connection(void* arg)
{
    uint32_t connfd;
    connfd = (uint32_t)arg;
    if(DEBUG_CONN) printf("current thread %lu , connfd=%u\n", (unsigned long)pthread_self(), connfd);
    uint8_t buffer[BUFFER_MAX*sizeof(uint8_t)] ;
    while(1)
    {
        
        int n = recv(connfd, buffer, BUFFER_SIZE, 0);
        if(n>0)
        {
            uint32_t *tmp = (uint32_t *) buffer;
            //if(DEBUG_CONN) printf("connection_handler n=%d, header :%d,%d,%d,%d\n",n, *tmp,*(tmp+1),*(tmp+2),*(tmp+3));
            switch(tmp[0])
            {
                case REQUEST_DEVICE_INFO:
                    if(enqueue(get_queue(Q_TYPE_DEVICE), buffer, connfd))
                    {
                        queue_notify(get_queue(Q_TYPE_DEVICE));
                    }
                    break;
                default:
                   //if(DEBUG_CONN) printf("do nothing just break.");
                    break;
            }
            memset(buffer,0,BUFFER_MAX);
        }
    }

}
