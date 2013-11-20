/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: queue.h
*         Desc: 
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-18 13:12:15
*      History:
*
********************************************************************************/
#ifndef QUEUE_H
#define QUEUE_H

#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>


typedef struct node_t {
    void *data;
    struct node_t *next;
} NODE;

typedef struct queue_t {
    NODE *head;
    NODE *tail;
    int counter;
    pthread_mutex_t lock;
} QUEUE;

int init_queue(QUEUE *q);

int enqueue(QUEUE *q, void* data_p);

int dequeue(QUEUE *q, void** data_pp);

int queue_empty(QUEUE *q);

int queue_size(QUEUE *q);
#endif
