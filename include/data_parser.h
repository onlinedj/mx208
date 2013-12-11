/********************************************************************************
*
*     Copyright (C) 2013 Minxin Tech - All Rights Reserved.
*
*     FileName: data_parser.h
*         Desc: 
*       Author: Jacky Yang (yangxinle@minxintech.com)
*      Version: 0.0.1
*   LastChange: 2013-12-04 09:25:19
*      History:
*
********************************************************************************/
#include "queue.h"
#include <stdint.h>
#define INT_SIZE 4
#define HEADER_SIZE 20
#define GET_HEADER
#define GET_INT(x) (*((uint32_t *) x))
int get_header(HEADER *header, uint8_t **buffer);
int get_data(uint8_t **buffer, uint8_t *result);
uint32_t get_int(uint8_t **buffer);
