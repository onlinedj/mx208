/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: mxserver.h
*         Desc: mx daemon
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-15 14:01:22
*      History:
*
********************************************************************************/

#ifndef MX_SERVER_H
#define MX_SERVER_H

#define DEBUG_SERVER 1
#define SOCKET_FD_MAX 10
#define SOCKET_PORT_NORMAL 30100
#define SOCKET_PORT_MANAGE 8992
#define CREATE_SOCKET_FAILED -1;

typedef enum {
    eth0,eth1
} IFACE;

#endif
