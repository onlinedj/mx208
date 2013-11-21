#include "queue.h"

int init_queue(QUEUE *q)
{
    q->head = q->tail = NULL;
    q->counter = 0;
    
    pthread_mutex_init(&q->lock, NULL);
    
    return 1;
}

int enqueue(QUEUE *q, void *data)
{
    pthread_mutex_lock(&q->lock);
    NODE *node = (NODE *)malloc(sizeof(NODE));
    //TODO do malloc check
    node->data = data;
    node->next = NULL;
    NODE* temp = NULL;
    if(!q->tail)
        q->head = q->tail = node;
    else 
    {
        temp = q->tail;
        q->tail->next = node;
        q->tail = node;
    }
    q->counter++;
    /*printf("enq    q->counter=%d,q->node:%p,%d,%p\n",q->counter,node,*((int*)node->data),temp);*/
    pthread_mutex_unlock(&q->lock);

    return 1;
}
int dequeue(QUEUE *q, void **data_pp)
{
    pthread_mutex_lock(&q->lock);
    int result = 0;
    if(q->head)
    {
        *data_pp = q->head->data;
        q->head->data = NULL;
        NODE *p = q->head;
        if(p->next)
        {
            q->head = q->head->next;
        }
        else 
        {
            q->head = q->tail = NULL ;
        }
        printf("deq    q->counter=%d,q->node:%p,%d,%p\n",q->counter,p,*((int*)p->data),q->head);
        free(p);
        q->counter--;
        result = 1;
    }
    else
    {
        //printf("nodata in q\n");
        *data_pp = NULL;
        result = 0;
    }
    pthread_mutex_unlock(&q->lock);
    return result;
}

int queue_empty(QUEUE *q)
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
}

