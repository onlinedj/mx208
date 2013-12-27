#include "file_manager.h"
#include "commands.h"
#include "data_parser.h"
#include "data_composer.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FILE_PATH "/home/jacky/"
int create_file(uint8_t *name,uint32_t len, uint32_t file_size);
int delete_file(uint8_t *name,uint32_t len);
int read_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *out);
int write_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, const uint8_t *in);


int create_file(uint8_t *name,uint32_t len, uint32_t file_size)
{
    int fd = open(name, O_CREAT,S_IRWXU);
    if(fd>0){
        return 0; 
    }
    else 
    {
        return 100; 
    }
}
int delete_file(uint8_t *name,uint32_t len)
{
    int result = remove(name);
    if(!result)
    {
        return 0; 
    }
    else
    {
        return 100;
    }
}
int read_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, uint8_t *out)
{
    int fd = open(name, O_RDONLY);
    int real_offset = lseek(fd,offset,SEEK_SET);
    if(real_offset>=0)
    {
        int read = read(fd,out,size);
        if(read == size)
        {
            return read; 
        }
        else
        {
            return -1; 
        }
    
    }
    else
    {
        return -1; 
    }
    
}
int write_file(uint8_t *name,uint32_t len, uint32_t offset, uint32_t size, const uint8_t *in)
{
   int fd = open(name, O_WRONLY);
   int real_offset = lseek(fd,offset,SEEK_SET);
   if(real_offset>=0)
   {
       int write = write(fd,in,size);
       if(write == size)
       {
           return write; 
       }
       else
       {
           return -1; 
       }

   }
   else
   {
       return -1; 
   }

}

int process_command_file(uint8_t *params, uint8_t *result)
{

    int process_result = 0;
    HEADER header;
    get_header(&header,&params);
    uint8_t buffer[BUFFER_MAX];
    bzero(buffer,BUFFER_SIZE);
    memcpy(buffer,FILE_PATH,sizeof(FILE_PATH)-1);
    printf("process file header.func_id=%d\n",header.func_id);
    switch(header.func_id)
    {
    case FUNID_SDF_CREATEFILE:
        {
            int result = get_data(&params,buffer);
            if(result>0)
            {
                uint32_t buffer_size = get_int(&params);
                buffer[sizeof(FILE_PATH)-1+buffer_size] = '\0';
                uint32_t file_size = get_int(&params);
                if(!create_file(buffer,buffer_size, file_size))
                {
                    HEADER header;
                    header.func_id = FUNID_SDF_CREATEFILE;
                    header.data_size = 0;
                    header.param_sum = 0;
                    header.reserved = 0;
                    process_result+=set_header(&result,header);
                }
            }

            break;
        }
    case FUNID_SDF_DELETEFILE:
        {
            int result = get_data(&params,buffer);
            if(result>0)
            {
                uint32_t buffer_size = get_int(&params);
                buffer[sizeof(FILE_PATH)-1+buffer_size] = '\0';
                if(!delete_file(buffer,buffer_size))
                {
                    HEADER header;
                    header.func_id = FUNID_SDF_DELETEFILE;
                    header.data_size = 0;
                    header.param_sum = 0;
                    header.reserved = 0;
                    process_result+=set_header(&result,header);
                
                }
            }
            
            break;
        }
    case FUNID_SDF_READFILE:
        {
            int result = get_data(&params,buffer);
            if(result>0)
            {
                uint32_t buffer_size = get_int(&params);
                buffer[sizeof(FILE_PATH)-1+buffer_size] = '\0';
                uint32_t offset = get_int(&params);
                uint32_t read_len = get_int(&params);
                uint8_t my_buff[BUFFER_MAX];
                bzero(my_buff,BUFFER_SIZE);
                int size = read_file(buffer,buffer_size,offset,read_len,my_buff);
                if(size>0)
                {
                    HEADER header;
                    header.func_id = FUNID_SDF_READFILE;
                    header.data_size = sizeof(uint32_t)*3+size;
                    header.param_sum = 2;
                    header.reserved = 0;
                    process_result+=set_header(&result,header);
                    process_result+=set_int(&result,size);
                    process_result+=set_data(&result,my_buff,size);
                     
                }
            }

            break;
        }
    case FUNID_SDF_WRITEFILE:
        {
            int result = get_data(&params,buffer);
            if(result>0)
            {
                uint32_t buffer_size = get_int(&params);
                buffer[sizeof(FILE_PATH)-1+buffer_size] = '\0';
                uint32_t offset = get_int(&params);
                uint32_t write_len = get_int(&params);
                uint8_t my_buff[BUFFER_MAX];
                bzero(my_buff,BUFFER_SIZE);
                uint32_t my_buff_size = get_data(&params,my_buff);
                int size = write_file(buffer,buffer_size,offset,write_len,my_buff);
                if(size>0)
                {
                    HEADER header;
                    header.func_id = FUNID_SDF_READFILE;
                    header.data_size = 0;
                    header.param_sum = 0;
                    header.reserved = 0;
                    process_result+=set_header(&result,header);
                     
                }
            }
            break;
        }
    default:
        break;
    }
}
