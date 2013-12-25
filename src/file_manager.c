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

}
