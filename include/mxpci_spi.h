#ifndef PCI_SPI_H
#define PCI_SPI_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mxpciio.h"

/******************************************************
 * FlashUserInfo - For User Read/Write Flash          *
 *  @addr:  Flash Chip Address,                       *
 *			Address range 0x0000 0000h - 0x007F FFFFh *    
 *  @len:   Length                                    *
 *  @buf:   Data Pointer                              *
 *******************************************************/
typedef struct flashuserinfo {
	unsigned int addr;
	unsigned int len;
	unsigned int *buf;
}FlashUserInfo;

/*********** IOCTL Command Define *************/
#define IOCTL_PCI_FLASH_READ		0x03000001
#define IOCTL_PCI_FLASH_FASTRD		0x03000002
#define IOCTL_PCI_FLASH_DORD		0x03000003
#define IOCTL_PCI_FLASH_QORD		0x03000004
#define IOCTL_PCI_FLASH_WRITE		0x03000005
#define IOCTL_PCI_FLASH_DIWR		0x03000006
#define IOCTL_PCI_FLASH_QIWR		0x03000007
#define IOCTL_PCI_FLASH_ERASE64K	0x03000008
#define IOCTL_PCI_FLASH_ERASE4K		0x03000009
#define IOCTL_PCI_FLASH_CHIPERASE	0x0300000A
#define IOCTL_PCI_FLASH_ERANDWR		0x0300000B
#define IOCTL_PCI_FLASH_READID		0x0300000C
#define IOCTL_PCI_FLASH_RDSR		0x0300000D
#define IOCTL_PCI_FLASH_OPCODE		0x0300000E

#ifdef __cplusplus
}
#endif

#endif
