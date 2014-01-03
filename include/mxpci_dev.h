#ifndef MXPCI_DEV_H   /* prevent circular inclusions */
#define MXPCI_DEV_H   /* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

#include "mxpciio.h"

/************************************************
 * PCIState - Get PCIe state from driver        *
 *  @Version:   Hardware design version info    *
 *  @LinkState: Link State - up or down         *
 *  @LinkSpeed: Link Speed                      *
 *  @LinkWidth: LinkWidth                       *
 *  @VendorId:  Vendor ID                       *
 *  @DeviceId:  Device ID                       *
 *  @IntMode:   Legacy or MSI interrupts        *
 *  @MPS:       Max Payload Size                *
 *  @MRRS:      Max Read Request Size           *
 ************************************************/
typedef struct {
	unsigned int Version;       /**< Hardware design version info */
	int LinkState;              /**< Link State - up or down */
	int LinkSpeed;              /**< Link Speed */
	int LinkWidth;              /**< Link Width */
	unsigned int VendorId;      /**< Vendor ID */
	unsigned int DeviceId;      /**< Device ID */
	int IntMode;                /**< Legacy or MSI interrupts */
	int MPS;                    /**< Max Payload Size */
	int MRRS;                   /**< Max Read Request Size */
} PCIState;

/************************************************
 * DevBaseInfo - Get PCI Base Address And Irq	*
 *	@irq:		Irq Number						*
 *	@phyAddr:	PCI Bar[0 - 5] Phyics Address	*
 *	@virAddr:	PCI Bar[0 - 5] Virtual Address	*
 *	@pdev:		PCI Devices						*
 ************************************************/
typedef struct {
	int irq;
	unsigned long phyAddr;
	unsigned long virAddr;
	struct pci_dev *pdev;
}DevBaseInfo;

/******************************************************
 * WngUserInfo - White Noise Genration user structure *
 *  @WngData:   WNG Data Pointer                      *
 *  @len:       Data Length(Byte)                     *
 *******************************************************/
typedef struct wnguserinfo{
	unsigned int *WngData;
	unsigned int len;
}WngUserInfo;

/***** Debug PCI BAR[0] All Adress *****/
typedef struct pciuserinfo{
	unsigned int *Data;
	unsigned int len;
	unsigned int offset;
}PciUserInfo;


/* Link States */
#define LINK_UP             1           /**< Link State is Up */
#define LINK_DOWN           0           /**< Link State is Down */

/* PCI-related states */
#define INT_MSIX            0x3         /**< MSI-X Interrupts capability */
#define INT_MSI             0x2         /**< MSI Interrupts capability */
#define INT_LEGACY          0x1         /**< Legacy Interrupts capability */
#define INT_NONE            0x0         /**< No Interrupt capability */
#define LINK_SPEED_25       1           /**< 2.5 Gbps */
#define LINK_SPEED_5        2           /**< 5 Gbps */

/* PCI Card Device IOCTL Command */
#define MX_MAGIC					'M'
#define IOCTL_PCI_GETSTATUS			_IOR(MX_MAGIC, 1, PCIState)
#define IOCTL_PCI_WNG_READ			_IOWR(MX_MAGIC, 4, WngUserInfo)
#define IOCTL_PCI_READ_DATA			_IOR(MX_MAGIC, 5, PciUserInfo)
#define IOCTL_PCI_WRITE_DATA		_IOW(MX_MAGIC, 6, PciUserInfo)

int GetBaseInfo(unsigned int barNum, DevBaseInfo *info);
int checkintertuptsource(int intrmask);
void EnableScmIntrBit(int intrmask);

/************* SCM Function Define ****************/
#define MXPCISMCADDR_OFFSET			0x280000
#define SCMRead(BaseAddress, Offset)        \
	  XIo_In32((BaseAddress) + (Offset))

#define SCMWrite(BaseAddress, Offset, Data)     \
	  XIo_Out32((BaseAddress)+(Offset), (Data))

/********** SCM Register Definitions ***************/
#define REG_SCMST_OFFSET	0x0
#define REG_SCMEN_OFFSET	0x4

/***** SCM interrupt Bit Mask *****/
#define INTR_DMA_CH0	(1 << 0)
#define INTR_DMA_CH1	(1 << 1)
#define INTR_DMA_CH2	(1 << 2)
#define INTR_DMA_CH3	(1 << 3)
#define INTR_DMA_SHM	(1 << 4)
#define INTR_DMA_SM4	(1 << 5)
#define INTR_DMA_SSX	(1 << 6)
#define INTR_DMA_ICC	(1 << 7)
#define INTR_DMA_SPI	(1 << 8)
#define INTR_DMA_EMI	(1 << 9)
#define INTR_DMA_WDT	(1 << 10)

#ifdef __cplusplus
}
#endif

#endif
