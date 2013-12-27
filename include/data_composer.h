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
#ifndef DATA_COMPOSER_H
#define DATA_COMPOSER_H
#include "queue.h"
#include <stdint.h>
#ifndef DATA_PARSER_H
#define INT_SIZE 4
#define LONG_SIZE 8
#endif
int set_header(uint8_t **buffer, HEADER *header);
int set_data(uint8_t **buffer, uint8_t *in, uint32_t in_size);
uint32_t set_int(uint8_t **buffer, uint32_t data);
uint64_t set_long(uint8_t **buffer, uint32_t data);
#endif
