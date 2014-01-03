#include "data_composer.h"

#include <stdio.h>
#include <string.h>

/*static int total = 0;
static int count = 0;
static uint8_t **mptr;*/

int set_header(uint8_t **buffer,HEADER header)
{
   memcpy(*buffer,&header,sizeof(HEADER)); 
   return sizeof(HEADER);
}
int set_data(uint8_t **buffer, uint8_t *in, uint32_t in_size)
{
    memcpy(*buffer,&in_size,INT_SIZE);
    *buffer+=INT_SIZE;
    memcpy(*buffer,in,in_size);
    *buffer+=in_size;
    return INT_SIZE+in_size;
}
uint32_t set_int(uint8_t **buffer, uint32_t data)
{
    uint32_t int_size = INT_SIZE;
    memcpy(*buffer,&int_size,INT_SIZE);
    *buffer+=INT_SIZE;
    memcpy(*buffer,&data,INT_SIZE);
    *buffer+=INT_SIZE;
    return INT_SIZE*2;
}
uint64_t set_long(uint8_t **buffer, uint32_t data)
{
    uint32_t long_size = LONG_SIZE;
    memcpy(*buffer,&long_size,INT_SIZE);
    *buffer+=INT_SIZE;
    memcpy(*buffer,&data,LONG_SIZE);
    *buffer+=LONG_SIZE;
    return INT_SIZE+LONG_SIZE;
}

/*int init_composer(uint8_t **ptr)
{
    
    total = 0;
    count = 0;
    mptr = ptr;
}
int get_write_size()
{
    return total+sizeof(HEADER);
}
int get_parameter_size()
{
    return total;
}
int get_count()
{
    return count;
}*/
