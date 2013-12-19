#include "data_parser.h"
#include <stdio.h>
#include <string.h>

/**
 * get an integer from buffer data,and move the cursor on.
 */
uint32_t get_int(uint8_t **buffer)
{
//    printf("buffer=%p,bufferp=%p,bufferpp=%p\n",*buffer,buffer,&buffer);
    uint32_t result = GET_INT(*buffer);
    printf("result=%u\n",result);
    *buffer+=INT_SIZE;
    return result;
}

uint64_t get_long(uint8_t **buffer)
{
//    printf("buffer=%p,bufferp=%p,bufferpp=%p\n",*buffer,buffer,&buffer);
    uint64_t result = GET_LONG(*buffer);
    printf("result=%u\n",result);
    *buffer+=LONG_SIZE;
    return result;
}

int get_header(HEADER *header, uint8_t **buffer)
{
    header->func_id = get_int(buffer);
    header->data_size = get_int(buffer);
    header->param_sum = get_int(buffer);
    header->reserved =  get_int(buffer);
    header->socketfd = get_int(buffer);
}


int get_data(uint8_t **buffer, uint8_t *result)
{
    uint32_t data_len = get_int(buffer);
    printf("get_data done len=%d\n",data_len);
    memcpy(result, *buffer, data_len);
    *buffer += data_len;
    return data_len;
}

/*int main(int argc, const char *argv[])
{
    uint8_t tmp[8];
    uint32_t *tmp32 = (uint32_t *)tmp;
    *tmp32 = 1023;
    *++tmp32 = 2049;
    uint8_t *tmp8 = tmp;
    printf("tmp=%p , tmp8=%p \n",&tmp,&tmp8);
    printf("int=%u\n", get_int(&tmp8));
    printf("int=%u\n", get_int(&tmp8));
    return 0;
}*/
