#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "miracl.h"
#include "sm2.h"
#include "mxpci_spi.h"

int main(int argc,char *argv[])
{
	unsigned char aa[32];
	unsigned char *wx=aa;
	int a[32];
	int *wxlen=a;
	unsigned char bb[32];
	unsigned char *wy=bb;
	int b[32];
	int *wylen=b;
	unsigned char cc[32];
	unsigned char *privkey=cc;
	int c[32];
	int *privkeylen=c;
	sm2_keygen(wx, wxlen, wy, wylen, privkey, privkeylen);
	int i =0;
	for(i=0;i<32;i++)
	{
		printf("%d\n",privkey[i]);
	}
	return 0;
}
