#include "device_manager.h"

#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "mx_std.h"
#include "commands.h"
#include "mxpci_spi.h"

#include "sm/demo_alo.h"

void alo_ECBencrpyt(const U8 *in, U8 *out,const U32 length, const U8 *key,const U32 enc)
{
    sm4_ecb_encrypt(in,out,length,key,enc);
}


int write_device_info()
{
    
    struct DeviceInfo_st info;
    memset(&info,0,sizeof(info));
    memcpy(info.IssuerName,"mx tech",7);
    memcpy(info.DeviceName,"mx 208",6);
    memcpy(info.DeviceSerial,"123456789",9);
    info.DeviceVersion=1;
    info.StandardVersion=2;
    info.AsymAlgAbility[0] = 3;
    info.AsymAlgAbility[1] = 4;
    info.SymAlgAbility = 5;
    info.HashAlgAbility = 6;
    info.BufferSize = 1024;
    
    

    int fd;
    fd = open("/dev/mxpcispi", O_WRONLY);

    if(fd > 0)
    {
        printf("open successfully\n");
        FlashUserInfo userinfo;
        userinfo.addr = 0x007E0000;
        userinfo.len = sizeof(info);
        userinfo.buf = &info;
        int error = ioctl(fd, IOCTL_PCI_FLASH_WRITE, &userinfo);
        printf("close file errorno=%d\n",error);
        close(fd);
        return 0;
    }
    else
    {
        printf("open failed:%s\n", strerror(errno));
        return (-1);
    }

}
int read_device_info(struct DeviceInfo_st *info)
{
    
    int fd;
    fd = open("/dev/mxpcispi", O_RDONLY);

    if(fd > 0)
    {
        printf("open successfully\n");
        FlashUserInfo userinfo;
        userinfo.addr = 0x007E0000;
        userinfo.len = sizeof(struct DeviceInfo_st);
        userinfo.buf = info;
        int error = ioctl(fd, IOCTL_PCI_FLASH_READ, &userinfo);
        printf("close file errorno=%d\n",error);
        close(fd);
        return 0;
    }
    else
    {
        printf("open failed:%s\n", strerror(errno));
        return (-1);
    }

}

int process_command_device(uint8_t *params, uint8_t *result)
{
    uint32_t *tmp = (uint32_t *) params;
    uint32_t command = tmp[0];
    int total = 0;
    switch(GET_ID(command))
    {
    case GET_DEVICE_INFO:
        {
            uint32_t my[4] = {(uint32_t)GET_DEVICE_INFO,sizeof(struct DeviceInfo_st)+sizeof(uint32_t),1,0};
            memcpy(result,my,sizeof(uint32_t)*4);
            uint32_t data_size = sizeof(struct DeviceInfo_st);
            memcpy(result+sizeof(uint32_t)*4,&data_size,sizeof(uint32_t));

            struct DeviceInfo_st info;
            memset(&info, 0, sizeof(info));
            read_device_info(&info);
            printf("info : %s,%s,%s\n",info.IssuerName,info.DeviceName,info.DeviceSerial);
            memcpy(result+sizeof(uint32_t)*5,&info,sizeof(info));
            total = sizeof(uint32_t)*5+sizeof(info);
            break;

        }
    default:

        break;
    } 
    return total;
}
