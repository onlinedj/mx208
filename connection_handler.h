/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: connection_handler.h
*         Desc: 
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-15 14:17:41
*      History:
*
********************************************************************************/
#ifndef CONNECTION_HANDLER_H
#define CONNECTION_HANDLER_H

#include <stdio.h>
#include <pthread.h>

#define HEADER_SIZE_UINT 4

typedef struct message_t {
    int msg_id;
    int type;
    char msg_body[256];
} MESG;
void *handle_connection(void *arg);
#endif
