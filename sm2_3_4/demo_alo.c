#include "demo_alo.h"

int alo_getKeypair(ECCrefPublicKey pubkey,ECCrefPrivateKey privkey)
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
        unsigned char *privkeys=cc;
        int c[32];
        int *privkeylen=c;
		int result;
        result = sm2_keygen(wx, wxlen, wy, wylen, privkeys, privkeylen);
		if(result < 1)
		{
			return result;
		}
		int i;
		for(i =0;i<32;i++)
		{
			pubkey.x[i] = wx[i];
		}
		for(i =0;i<32;i++)
		{
			pubkey.y[i] = wy[i];
		}
		//pubkey.x = wx;
		//pubkey.y = wy;
		pubkey.bits = 32;
		for(i =0;i<32;i++)
		{
			privkey.D[i] = privkeys[i];
		}
		//privkey.D = privkeys;
		privkey.bits = 32;
		
		
		printf("%d\n\n",result);
		
		return result;
		
}

int alo_ECCencrpyt(unsigned char *msg, int msglen, ECCrefPublicKey pubkey ,unsigned char *outmsg)
{
	//unsigned char *wx = pubkey.x;
	//int wxlen = 32;
	//unsigned char *wy = pubkey.y;
	//int wylen = 32;
	
	//int result;
	
		unsigned char aa[32];
        unsigned char *wx=aa;
        int a[32];
        int *wxlen=a;
        unsigned char bb[32];
        unsigned char *wy=bb;
        int b[32];
        int *wylen=b;
        unsigned char cc[32];
        unsigned char *privkeys=cc;
        int c[32];
        int *privkeylen=c;
		int result;
        result = sm2_keygen(wx, wxlen, wy, wylen, privkeys, privkeylen);
	
	result = sm2_encrypt(msg, msglen, wx, wxlen, wy, wylen, outmsg);
	printf("%d\n\n",result);
	
	return result;
}

int alo_ECCdecrypt(unsigned char *msg, int msglen, ECCrefPrivateKey privkey, unsigned char *outmsg)
{
	unsigned char *privkeys = privkey.D;
	int privkeylen = privkey.bits;
	
	int result; 	
	result = sm2_decrypt(msg, msglen,privkeys,  privkeylen, outmsg);
	printf("%d\n\n",result);
	return result;
}

void alo_ECBencrpyt(const U8 *in, U8 *out,const U32 length, const U8 *key,const U32 enc)
{
	sm4_ecb_encrypt(in,out,length,key,enc);
}

int main(int argc,char *argv[])
{
      // ECCrefPublicKey pubkey;
	  // ECCrefPrivateKey privkey;
	  // alo_getKeypair(pubkey,privkey);
	  // unsigned char msg[32] = {0};
	  // unsigned char aa[128];
	  // unsigned char *encrpyt_outmsg = aa;
	  // int msglen = 32;
	   // unsigned char outs[5];
	  // unsigned char *decrypt_outmsg = outs;
	  // alo_ECCencrpyt(msg, msglen,  pubkey ,encrpyt_outmsg);
	   //alo_ECCdecrypt(encrpyt_outmsg, 101, privkey, decrypt_outmsg);
	 // int i;
	 // for(i=0;i<5;i++)
	 // {
	//	printf("%c\n",decrypt_outmsg[i]);
	 // }
	   unsigned char ins[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	   unsigned char keys[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	   U8 *in = ins;
	   U8 *key = keys;
	   
	    unsigned char outs[16];
		U8 *out = outs;
	   alo_ECBencrpyt(in,out,16,key,1);
	   int i;
	   for(i =0; i<16;i++)
	   {
		printf("%X",out[i]);
	   }
	   
}