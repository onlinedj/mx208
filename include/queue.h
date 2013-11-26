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

#define BUFFER_MAX 65536
#define BUFFER_SIZE BUFFER_MAX*sizeof(uint8_t)

#define Q_TYPE_DEVICE 0
#define Q_TYPE_ALGORITHM 1
#define Q_TYPE_KEY 2
#define Q_TYPE_FILE 3

typedef struct header_t {
    uint32_t func_id;
    uint32_t data_size;
    uint32_t param_sum;
    uint32_t reserved;
    uint32_t socketfd;
} HEADER;


typedef struct node_t {
    HEADER header;
    uint8_t *data;
    struct node_t *next;
} NODE;

typedef struct queue_t {
    NODE *head;
    NODE *tail;
    int counter;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} QUEUE;

int init_queue(QUEUE **q);

int destroy_queue(QUEUE *q);

void read_buffer(uint8_t *buffer, NODE *node);

int enqueue(QUEUE *q, uint8_t *buffer, uint32_t connfd);

int dequeue(QUEUE *q, uint8_t *buffer);

/*int queue_empty(QUEUE *q);

int queue_size(QUEUE *q);*/

void queue_wait(QUEUE *q);
void queue_notify(QUEUE *q);
#endif
