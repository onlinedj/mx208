#include "connection_handler.h"

#include <stdint.h>

#include "queue.h"
#include "command_handler.h"


void *handle_connection(void* arg)
{
    long connfd;
    connfd = (long)arg;
    printf("current thread %u , connfd=%ld\n", (unsigned int)pthread_self(), connfd);
    while(1)
    {
        uint32_t *header = (uint32_t *)malloc(sizeof(uint32_t)*5);
        int n = recv(connfd, header, sizeof(uint32_t)*4,0);
        if(n>0)
        {
            *(header+4) = connfd;
            printf("header:%d,%d,%d,%d,%d\n",*header,*(header+1),*(header+2),*(header+3),*(header+4));
            switch(*header)
            {
                case 1:
                    enqueue(get_queue(1), header);
                    break;
                default:
                    printf("do nothing just break.");
                    break;
            }
        }
    }

}
