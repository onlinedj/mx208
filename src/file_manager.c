#include "file_manager.h"
#include "commands.h"

int create_file(uint8_t *name,uint32_t len, uint32_t file_size);
int delete_file(uint8_t *name,uint32_t len);
int read_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *out);
int write_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *in);


int create_file(uint8_t *name,uint32_t len, uint32_t file_size)
{
    
}
int delete_file(uint8_t *name,uint32_t len);
int read_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *out);
int write_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *in);

int process_command_file(uint8_t *params, uint8_t *result)
{

    int process_result = 0;
    HEADER header;
    get_header(&header,&params);
    printf("process file header.func_id=%d\n",header.func_id);
    switch(header.func_id)
    {
    case FUNID_SDF_CREATEFILE:
        {
            break;
        }
    case FUNID_SDF_DELETEFILE:
        {
            break;
        }
    case FUNID_SDF_READFILE:
        {
            break;
        }
    case FUNID_SDF_WRITEFILE:
        {
            break;
        }
    default:
        break;
    }
}
