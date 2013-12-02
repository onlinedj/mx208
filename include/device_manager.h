/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: device_manager.h
*         Desc: 
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-11-27 14:53:54
*      History:
*
********************************************************************************/
#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H
#include <stdint.h>
int write_device_info();
int process_command_device(uint8_t *params, uint8_t *result);
#endif
