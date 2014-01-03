#ifndef PCI_MCU_H
#define PCI_MCU_H

#ifdef __cplusplus
extern "C" {
#endif

/******* Vaule Define *******/
#define ENCRYKEYLEN			4
#define ENCRYCBCIVLEN		4
/**** Encryption\Decryption Mode ****/
#define ENCRYMODE_ECB		0x0
#define ENCRYMODE_CBC		0x1
/****** Encryption\Decryption *******/
#define ENCRYOPCODE			0x0
#define DECRYOPCODE			0x1

/************ MCU Flash **************/
#define MCUFLASHRD          1
#define MCUFLASHWR          0
#define MCUFLASHLEN         3064
#define MCUFLASHADDRMASK    0xFFFF

/*******************************************
 *McuUserInfo - For User Read/Write SRAM   *
 *	@addr:	SRAM Address				   *
 *	@len:	Length						   *
 *	@buf:	Data Pointer				   *
 *******************************************/
typedef struct mcuuserinfo {
	unsigned int addr;
	unsigned int len;
	unsigned int *buf;
}McuUserInfo;

/****************************************************
 *McuFlashUserInfo - For User Read/Write MCU Flash  *
 *	@addr:  Mcu Flash Address(0x0 -- 0xFFFF)        *
 *  @len:   Length(byte), Once Max Length 3036      *
 *	@buf:   Data Pointer                            *
 *  @write: 0:Write, 1:Read                         *
 *****************************************************/
typedef struct mcuflashuserinfo {
	unsigned int addr;
	unsigned int len;
	unsigned int *buf;
	unsigned char write;
}McuFlashUserInfo;

/**************************************************
 * McuUserEncry - For User Encryp\Decryp		  *
 *	@mode:	Encryption\Decryption Type			  *
 *	@encry:	0:Encryption, 1:Decryption			  *
 *	@len:	Data Length, Only For				  *
 *			Encryption\Decryption Data Length	  *
 *	@key:	Key Data							  *
 *	@CbcIv:	If mode == CBC, Fill CBC IV			  *
 *	@EncryData: Encryption\Decryption Data		  *
 **************************************************/
typedef struct mcuuserencry {
	unsigned char mode;		/* ECB or CBC */
	unsigned char encry;				
	unsigned int len;					
	unsigned int key[ENCRYKEYLEN];
	unsigned int CbcIv[ENCRYCBCIVLEN];
	unsigned int *EncryData;			
}McuUserEncry;


/************************* IOCTL Command Define *************************/
#define MX_MAGIC                'M'
#define IOCTL_PCI_MCU_READ		_IOR(MX_MAGIC, 0x04000001, McuUserInfo)
#define IOCTL_PCI_MCU_WRITE		_IOW(MX_MAGIC, 0x04000002, McuUserInfo)
#define IOCTL_PCI_MCU_RESET		_IOW(MX_MAGIC, 0x04000003, int)
#define IOCTL_PCI_MCU_ENCRYOP	_IOW(MX_MAGIC, 0x04000004, McuUserEncry)
#define IOCTL_PCI_MCU_FLASH		_IOW(MX_MAGIC, 0x04000005, McuFlashUserInfo)

#ifdef __cplusplus
}
#endif

#endif
