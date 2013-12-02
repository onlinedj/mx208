/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: command_handler.h
*         Desc: handles request
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-18 10:16:27
*      History:
*
********************************************************************************/
#ifndef COMMAND_HANDLER_H
#define COMMAND_HANDLER_H

#include "queue.h"
#include "commands.h"

#define DEBUG_COMM 1

#define THREAD_COUNT 4

void init_queues();
void destroy_queues();
void* handle_command(void *arg);
QUEUE* get_queue(int type);

#endif
