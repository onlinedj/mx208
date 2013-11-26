#include "queue.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>



int init_queue(QUEUE **q)
{
    QUEUE *tmp = (QUEUE *) malloc(sizeof(QUEUE));
    bzero(tmp,sizeof(QUEUE));    
    tmp->head = tmp->tail = NULL;
    tmp->counter = 0;

    pthread_mutex_init(&tmp->lock, NULL);
    pthread_cond_init(&tmp->cond, NULL);

    *q = tmp;
    
    return RESULT_SUCCESS;
}

int destroy_queue(QUEUE *q)
{
    
    while(q->head)
    {
        NODE *tmp = q->head; 
        q->head = q->head->next;

        free(tmp->data);
        tmp->data = NULL;
        free(tmp);
    }
    q->head = q->tail = NULL;

    free(q);
    return RESULT_SUCCESS;
}

void queue_wait(QUEUE *q)
{
    pthread_mutex_lock(&q->lock);
    pthread_cond_wait(&q->cond,&q->lock);
    pthread_mutex_unlock(&q->lock);
}

void queue_notify(QUEUE *q)
{
    pthread_mutex_lock(&q->lock);
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);
}

void read_buffer(uint8_t *buffer, NODE *node)
{
    uint32_t *tmp = (uint32_t *)buffer;
    node->header.func_id = *(tmp);        
    node->header.data_size = *(tmp+1);
    node->header.param_sum = *(tmp+2);
    node->header.reserved = 0;
    if(node->header.data_size > 0)
        node->data = (uint8_t *)malloc(node->header.data_size);
    else 
        node->data = NULL;
}

int enqueue(QUEUE *q, uint8_t *buffer, uint32_t connfd)
{
    pthread_mutex_lock(&q->lock);

    NODE *node = (NODE *)malloc(sizeof(NODE));
    read_buffer(buffer,node);
    node->header.socketfd = connfd;
    node->next = NULL;
    int wait_in_queue = 0;
    NODE* temp = NULL;
    if(!q->tail)
    {
        q->head = q->tail = node;
        wait_in_queue = 1;
    }
    else 
    {
        temp = q->tail;
        q->tail->next = node;
        q->tail = node;
        wait_in_queue = 0;
    }

    if(DEBUG_Q) printf("node header:%u,%u,%u,%u,%u\n",node->header.func_id,node->header.data_size,node->header.param_sum,node->header.reserved,node->header.socketfd);
    q->counter++;
    if(DEBUG_Q) printf("enq    q->counter=%d,q->node:%p,q->node pre:%p\n",q->counter,node,temp);

    pthread_mutex_unlock(&q->lock);
    

    return wait_in_queue;
}
int dequeue(QUEUE *q, uint8_t *buffer)
{
    pthread_mutex_lock(&q->lock);
    int result = 0;
    if(q->head)
    {
        memcpy(buffer,&(q->head->header),sizeof(HEADER));
        if(q->head->data)
        {
            memcpy(buffer+sizeof(HEADER),q->head->data,q->head->header.data_size);
            free(q->head->data);
            q->head->data = NULL;
        }
        NODE *p = q->head;
        if(p->next)
        {
            q->head = q->head->next;
        }
        else 
        {
            q->head = q->tail = NULL ;
        }
        free(p);

        if(DEBUG_Q) printf("deq    q->counter=%d,q->node:%p,q->node pre:%p\n",q->counter,q->head,p);
        q->counter--;
        result = RESULT_SUCCESS;
    }
    else
    {
        //printf("nodata in q\n");
        result = RESULT_FAILED;
    }
    pthread_mutex_unlock(&q->lock);
    return result;
}

/*int queue_empty(QUEUE *q)
{
    pthread_mutex_lock(&q->lock);
    int n = (NULL == q->head);
    pthread_mutex_unlock(&q->lock);
    return n;
}

int queue_size(QUEUE *q)
{
    pthread_mutex_lock(&q->lock);
    int n =  q->counter;
    pthread_mutex_unlock(&q->lock);
    return n;
}*/

