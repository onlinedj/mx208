#include "algorithm.h"

int ALG_SDF_GenerateRandom(unsigned int uiLength,unsigned char *pucRandom)
{
 	int fd;
	//unsigned int *data = NULL;
	WngUserInfo wngInfo;
	fd = open("/dev/mxpci", O_WRONLY);
	if(uiLength % 4 != 0)
	{
		return 0;
	}
	if(fd > 0)
	{
		//pucRandom = (unsigned int *)malloc(uiLength);
		wngInfo.WngData = pucRandom;
        wngInfo.len = uiLength;
		ioctl(fd, IOCTL_PCI_WNG_READ, &wngInfo);
		
		return 1;
	}
	else
	{
		return 0;
	}
	
}

int ALG_SDF_GenerateKeyPair_ECC(unsigned char *wx,  unsigned char *wy, unsigned char *privkey)
{
	int result;
	int x_len,y_len,d_len;
	result = sm2_keygen(wx,&x_len,wy,&y_len,privkey,&d_len);
	//pucPublicKey.bits = 128;
	//pucPrivateKey.bits = 128;
	printf("getecckey = %d\n",result);
	printf("\n");
	return result;
	
}

int ALG_SDF_GenerateKeyWith_ECC(ECCrefPublicKey pucPublicKey,unsigned int uiKeyBits,unsigned char *outdata,unsigned int pubkeyLength)
{
	int result;
	unsigned char *sessionkey = NULL;
	sessionkey = (unsigned int *)malloc(uiKeyBits);	
	//unsigned char outdata[1024];
	//get sessionkey
	ALG_SDF_GenerateRandom(uiKeyBits,sessionkey);

	//result = sm2_encrypt(sessionkey, uiKeyBits, wx, pubkeyLength, wy, pubkeyLength, outdata);
	result = sm2_encrypt(sessionkey,uiKeyBits,&pucPublicKey.x,pubkeyLength,&pucPublicKey.y,pubkeyLength,outdata);
	printf("encrpty = %d\n",result);
	
	return result;
}

int ALG_SDF_Encrytp_ECC(unsigned char *inputdata,ECCrefPublicKey pucPublicKey,unsigned int pubkeyLength,unsigned int uiDataLength,unsigned char *outdata)
{
	int result;
	result = sm2_encrypt(inputdata,uiDataLength,&pucPublicKey.x,pubkeyLength,&pucPublicKey.y,pubkeyLength,outdata);
	return result;
}

int ALG_SDF_ImportKeyWithISK_ECC(ECCrefPrivateKey pucPrivateKey,unsigned char *indata,unsigned int datalength,unsigned int privkeylength,unsigned char *outmsg)
{
	int result;
	unsigned char outdata[1024];
	result = sm2_decrypt(indata,datalength,&pucPrivateKey.D,privkeylength,outdata);
	printf("decrpty = %d\n",result);
	return result;
}

int ALG_SDF_Sign_ECC(ECCrefPrivateKey pucPrivateKey,ECCrefPublicKey pucPublicKey,unsigned char *pucDataInput,unsigned int uiInputLength,unsigned char *wr,  unsigned char *ws,unsigned char* outdata)
{
	unsigned char *hsm3;
	//unsigned char outdata[1024];
	hsm3 = sm3_e("1234567812345678",16,&pucPublicKey.x,32,&pucPublicKey.y,32,pucDataInput,uiInputLength,outdata);
	if (hsm3 == NULL)
	{
		return -1;
	}
	int result;
	int rdatalen,sdatalen;
	result = sm2_sign(outdata,32,&pucPrivateKey.D,32,wr,&rdatalen,ws,&sdatalen);
	printf("%d\n",rdatalen);
	printf("sign result = %d\n",result);
	return result;
	
}

int ALG_DirectSign_Ecc(ECCrefPrivateKey pucPrivateKey,unsigned char *pucDataInput,unsigned char *wr, unsigned char *ws,int rdatalen,int sdatalen)
{
	int result;	
	result = sm2_sign(pucDataInput,32,&pucPrivateKey.D,32,wr,&rdatalen,ws,&sdatalen);
	return result;
}

int ALG_SDF_Verify_ECC(ECCrefPublicKey pucPublicKey,ECCSignature pucSignature,unsigned char *pucDataInput,unsigned int uiInputLength)
{
	int result;
	result = sm2_verify(pucDataInput,32,&pucSignature.r,32,&pucSignature.s,32,&pucPublicKey.x,32,&pucPublicKey.y,32);
	printf("Verify result = %d\n",result);
	return result;
}

void ALG_SDF_Encrypt(unsigned char *key,int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData)
{
	int result;
	switch(uiAlgID)
	{
		case SGD_SM4_ECB:
		{
			sm4_ecb_encrypt(pucData, pucEncData, uiDataLength, key, SM4_ENCRYPT);
			break;
		}
		case SGD_SM4_CBC :
		{
			sm4_cbc_encrypt(pucData, pucEncData,uiDataLength, key, pucIV, SM4_ENCRYPT);
			break;
		}
		case SGD_SM4_CFB:
		{
			sm4_cfb_encrypt(pucData, pucEncData,uiDataLength, key, pucIV, SM4_ENCRYPT);
			break;
		}
		case SGD_SM4_OFB:
		{
			sm4_ofb_encrypt(pucData, pucEncData,uiDataLength, key, pucIV);
			break;
		}
	}
}

void ALG_SDF_Decrypt(unsigned char *key,int uiAlgID,unsigned char *pucIV,unsigned char *pucData,unsigned int uiDataLength,unsigned char *pucEncData)
{
	int result;
	switch(uiAlgID)
	{
		case SGD_SM4_ECB:
		{
			sm4_ecb_encrypt(pucData, pucEncData, uiDataLength, key, SM4_DECRYPT);
			break;
		}
		case SGD_SM4_CBC :
		{
			sm4_cbc_encrypt(pucData, pucEncData,uiDataLength, key, pucIV, SM4_DECRYPT);
			break;
		}
		case SGD_SM4_CFB:
		{
			sm4_cfb_encrypt(pucData, pucEncData,uiDataLength, key, pucIV, SM4_DECRYPT);
			break;
		}
		
	}
}

void ALG_SDF_CalculateMAC(unsigned char *key,int keylength,unsigned char *text, int textlen, unsigned char *hmac)
{
	sm3_hmac(key, keylength, text, textlen, hmac);
}

void ALG_SDF_HashInit(SM3_CTX *ctx)
{
	SM3_Init (ctx);
}

void ALG_SDF_HashUpdate(SM3_CTX *ctx, const void *data, int len)
{
	SM3_Update(ctx, data, len);
}

void ALG_SDF_HashFinalSM3_Final(unsigned char *md, SM3_CTX *ctx)
{
	void SM3_Final(md, ctx);
}

int process_command_algorithm(unsigned char *params,unsigned char *result)
{
	int funID = (int)params[0];
	int paramNum = (int)params[2];
	int dataLength = (int)params[1];
	printf("fun = %d\n",funID);
	switch(funID)
	{
		case SDF_GenerateRandom:
		{
			int uiLength = params[5];
			unsigned char *sessionkey = NULL;
			sessionkey = (unsigned int *)malloc(uiLength);	
			ALG_SDF_GenerateRandom(uiLength,sessionkey);
			result[0] = params[0];
			result[2] = params[2];
			result[1] = (uiLength + 1);
			result[4] = uiLength;
			memcpy((result+5),sessionkey,uiLength);
			break;
		}
		case SDF_GenerateKeyPair_ECC:
		{
			ECCrefPublicKey sm2publickey;
			ECCrefPrivateKey sm2privatekey;
			ALG_SDF_GenerateKeyPair_ECC(&sm2publickey.x,&sm2publickey.y,sm2privatekey.D);
			
			result[0] = params[0];
			result[2] = params[2];
			//result[1] = ();
			result[4] = 65;
			result[5] = 128;
			memcpy((result+6),&sm2publickey.x,32);
			memcpy((result+6+32),&sm2publickey.y,32);
			result[70] = 65;
			result[71] = 128;
			memcpy((result+6+32+32+2),&sm2privatekey.D,32);
			break;
		}
		case SDF_GenerateKeyWithIPK_ECC:	//phKeyHandle
		{
			int index;
			index = (int)params[5];
			int uiKeyBits = (int)params[7];
			unsigned char outdata[uiKeyBits+96];
			int type = COMBO_TYPE(TYPE_ENC_PUB,TYPE_ECC_PUB);
			KEYINFO keyinfo;
			//keyinfo = (unsigned int *)malloc(1024);
			int rv =  get_key(type, index, &keyinfo);
			ECCrefPublicKey sm2publickey;
			sm2publickey = keyinfo.data.ecc_puk;
			//memcpy(sm2publickey,&keyinfo.data.ecc_puk,sizeof(*sm2publickey));
			ALG_SDF_GenerateKeyWith_ECC(sm2publickey,32,outdata,32);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = uiKeyBits+96+64;
			memcpy((result+5),&sm2publickey.x,32);
			memcpy((result+5+32),&sm2publickey.y,32);
			memcpy((result+5+64),outdata,uiKeyBits+96);
		}
		case SDF_GenerateKeyWithEPK_ECC:	//phKeyHandle
		{
			
			int uiKeyBits = (int)params[5];
			printf("uiKeyBits = %d\n",uiKeyBits);
			ECCrefPublicKey sm2publickey;
			memcpy(&sm2publickey.x,params+10,32);
			memcpy(&sm2publickey.y,params+10+32,32);
			unsigned char outdata[uiKeyBits+96];
			ALG_SDF_GenerateKeyWith_ECC(sm2publickey,32,outdata,32);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = uiKeyBits+96+64;
			memcpy((result+5),&sm2publickey.x,32);
			memcpy((result+5+32),&sm2publickey.y,32);
			memcpy((result+5+64),outdata,uiKeyBits+96);
			
			result[6+uiKeyBits+96+64] = 1;
			
			break;
		}
		case SDF_ImportKeyWithISK_ECC:	//phKeyHandle
		{
			int index;
			index = (int)params[5];
			unsigned char *indata = (unsigned int *)malloc(1024);
			int dataLength;			
			dataLength = strlen(params+7+64);
			memcpy(indata,params+7+64,dataLength);
			
			int type = COMBO_TYPE(TYPE_ENC_PRI,TYPE_ECC_PRI);
			KEYINFO keyinfo;
			//keyinfo = (unsigned int *)malloc(1024);
			int rv =  get_key(type, index, &keyinfo);
			ECCrefPrivateKey sm2privatekey;
			sm2privatekey = (keyinfo.data).ecc_prk;
			
			unsigned char tempdata[1024];
			ALG_SDF_ImportKeyWithISK_ECC(sm2privatekey,indata,dataLength,32,tempdata);
			break;
		}
		case SDF_ExchangeDigitEnvelopeBaseOnECC:	
		{
			int index;
			index = (int)params[5];
			unsigned char *indata = (unsigned int *)malloc(1024);
			int dataLength;			
			dataLength = strlen(params+12+64+64);
			memcpy(indata,params+12+64+64,dataLength);
			
			ECCrefPublicKey sm2Outpublickey;
			ECCrefPrivateKey sm2Inprivatekey;
			int type = COMBO_TYPE(TYPE_ENC_PRI,TYPE_ECC_PRI);
			KEYINFO keyinfo;
			//keyinfo = (unsigned int *)malloc(1024);
			int rv =  get_key(type, index, &keyinfo);			
			sm2Inprivatekey = (keyinfo.data).ecc_prk;
			
			memcpy(&sm2Outpublickey.x,params+10,32);
			memcpy(&sm2Outpublickey.y,params+10+32,32);
			unsigned char tempdata[1024];
			ALG_SDF_ImportKeyWithISK_ECC(sm2Inprivatekey,indata,dataLength,32,tempdata);
			
			int tmpLength = strlen(tempdata);
			unsigned char outdata[tmpLength+96];
			ALG_SDF_Encrytp_ECC(tempdata,sm2Outpublickey,32,tmpLength,outdata);
			result[0] = params[0];
			result[2] = params[2];
			result[4] = tmpLength+96+64;
			memcpy((result+5),&sm2Outpublickey.x,32);
			memcpy((result+5+32),&sm2Outpublickey.y,32);
			memcpy((result+5+64),outdata,tmpLength+96);
			break;
		}
		case SDF_GenerateKeyWithKEK:		//phKeyHandle
		{
			int sessionKeyLength = (int)params[5];
			int uiAlgID = (int)params[7];
			int index = (int)params[9];
			unsigned char *sessionkey = NULL;
			sessionkey = (unsigned int *)malloc(sessionKeyLength);	
			ALG_SDF_GenerateRandom(sessionKeyLength,sessionkey);
			
			
			KEKINFO kekinfo;
			//kekinfo = (unsigned int *)malloc(1024);
			int rv = get_kek(index, &kekinfo);
			unsigned char *kek_key = &kekinfo.data;
			unsigned char pucEncData[1024];
			
			ALG_SDF_Encrypt(kek_key,uiAlgID,NULL,sessionkey,sessionKeyLength,pucEncData);
			int pucEncDataLenfth = strlen(pucEncData);
			result[0] = params[0];
			result[2] = params[2];
			
			result[4] = pucEncDataLenfth;
			memcpy((result+5),pucEncData,pucEncDataLenfth);
			result[5+pucEncDataLenfth] = 1;
			result[5+pucEncDataLenfth+1] = pucEncDataLenfth;
			
			break;
		}
		case SDF_ImportKeyWithKEK:	//phKeyHandle
		{
			int uiAlgID = (int)params[5];
			int index = (int)params[7];
			int keylength = (int)params[8];
			unsigned char *sessionkey = (unsigned int *)malloc(1024);
			memcpy(sessionkey,params+9,keylength);
			
			KEKINFO kekinfo;
			//kekinfo = (unsigned int *)malloc(1024);
			int rv = get_kek(index, &kekinfo);
			unsigned char *kek_key = &kekinfo.data;
			unsigned char pucEncData[1024];
			
			ALG_SDF_Decrypt(kek_key,uiAlgID,NULL,sessionkey,keylength,pucEncData);
			
			result[0] = params[0];
			result[2] = params[2];
			
			break;
		}
		case SDF_ExternalSign_ECC:
		{
			ECCrefPrivateKey sm2privatekey;
			memcpy(&sm2privatekey.D,params+8,32);
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int pucDataLength = params[8+32];
			memcpy(pucData,params+8+33,pucDataLength);
			int rdatalen;int sdatalen;
			ECCSignature sm2sign;
			ALG_DirectSign_Ecc(sm2privatekey,pucData,&sm2sign.r,&sm2sign.s,&rdatalen,&sdatalen);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = rdatalen + sdatalen;
			memcpy((result+5),&sm2sign.r,rdatalen);
			memcpy((result+5+rdatalen),&sm2sign.s,sdatalen);
			break;
		}
		case SDF_ExternalVerify_ECC:
		{
			ECCSignature sm2sign;
			ECCrefPublicKey sm2publickey;
			unsigned char *pucData = (unsigned int *)malloc(1024);
			memcpy(&sm2publickey.x,params+8,32);
			memcpy(&sm2publickey.x,params+8+32,32);
			int length = params[8+32+32];
			memcpy(pucData,params+8+32+32+1,length);
			memcpy(sm2sign.r,params+8+32+32+1+length+3,ECCref_MAX_LEN);
			memcpy(sm2sign.s,params+8+32+32+1+length+3+ECCref_MAX_LEN,ECCref_MAX_LEN);
			
			ALG_SDF_Verify_ECC(sm2publickey,sm2sign,pucData,ECCref_MAX_LEN);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = 1;
			//result[5] = result;
			break;
		}
		case SDF_InternalSign_ECC:
		{
			int index = (int)params[5];
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int pucDataLength = params[6];
			memcpy(pucData,params+7,pucDataLength);
			
			ECCrefPrivateKey sm2privatekey;
			int type = COMBO_TYPE(TYPE_SIGN_PRI,TYPE_ECC_SIGN);
			KEYINFO keyinfo;
			//keyinfo = (unsigned int *)malloc(1024);
			int rv =  get_key(type, index, &keyinfo);			
			sm2privatekey = (keyinfo.data).ecc_prk;
			
			int rdatalen;int sdatalen;
			ECCSignature sm2sign;
			ALG_DirectSign_Ecc(sm2privatekey,pucData,&sm2sign.r,&sm2sign.s,&rdatalen,&sdatalen);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = rdatalen + sdatalen;
			memcpy((result+5),&sm2sign.r,rdatalen);
			memcpy((result+5+rdatalen),&sm2sign.s,sdatalen);
			break;
		}
		case SDF_InternalVerify_ECC:
		{
			ECCSignature sm2sign;
			ECCrefPublicKey sm2publickey;
			int index = (int)params[5];
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int pucDataLength = params[6];
			memcpy(pucData,params+7,pucDataLength);
			
			memcpy(sm2sign.r,params+7+pucDataLength+3,ECCref_MAX_LEN);
			memcpy(sm2sign.s,params+7+pucDataLength+3+ECCref_MAX_LEN,ECCref_MAX_LEN);
			
			int type = COMBO_TYPE(TYPE_SIGN_PUB,TYPE_ECC_CIPH);
			KEYINFO keyinfo;
			//keyinfo = (unsigned int *)malloc(1024);
			int rv =  get_key(type, index, &keyinfo);			
			sm2publickey = (keyinfo.data).ecc_puk;
			
			ALG_SDF_Verify_ECC(sm2publickey,sm2sign,pucData,ECCref_MAX_LEN);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = 1;
			//result[5] = result;
			break;
		}
		case SDF_ExternalEncrytp_ECC:
		{
			ECCrefPublicKey sm2publickey;
			memcpy(&sm2publickey.x,params+8,32);
			memcpy(&sm2publickey.y,params+8+32,32);
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int length = params[8+32+32];
			memcpy(pucData,params+8+32+1+32,length);
			unsigned char outdata[1024];
			ALG_SDF_Encrytp_ECC(pucData,sm2publickey,ECCref_MAX_LEN,length,outdata);
			int uiKeyBits = strlen(outdata);
			result[0] = params[0];
			result[2] = params[2];
			result[4] = uiKeyBits+96+64;
			memcpy((result+5),&sm2publickey.x,32);
			memcpy((result+5+32),&sm2publickey.y,32);
			memcpy((result+5+64),outdata,uiKeyBits+96);
			
			break;
		}
		case SDF_ExternalDecrypt_ECC:
		{
			ECCrefPrivateKey sm2privatekey;
			memcpy(&sm2privatekey.D,params+8,32);
			
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int length = params[8+32];
			memcpy(pucData,params+8+32+1,length);
			
			unsigned char tempdata[1024];
			ALG_SDF_ImportKeyWithISK_ECC(sm2privatekey,pucData,length,32,tempdata);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = strlen(tempdata);
			memcpy((result+5),tempdata,strlen(tempdata));
			break;
		}
		case SDF_Encrypt:
		{
			
			unsigned char *key = (unsigned int *)malloc(1024);
			unsigned char *pucIV = (unsigned int *)malloc(1024);
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int keylength = (int)params[4];
			memcpy(key,params+5,keylength);
			int uiAlgID = (int)params[5+keylength+1];
			int IVlength = (int)params[5+keylength+2];
			memcpy(pucIV,params+5+keylength+3,IVlength);
			int pucdatalength = (int)params[5+keylength+3+IVlength+1];
			memcpy(pucData,params+5+keylength+3+IVlength+2,pucdatalength);
			unsigned char *pucEncData = (unsigned int *)malloc(1024);
			ALG_SDF_Encrypt(key,uiAlgID,pucIV,pucData,pucdatalength,pucEncData);
			int outdatalength = strlen(pucEncData);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = strlen(pucEncData);
			memcpy((result+5),pucEncData,strlen(pucEncData));
			result[5+strlen(pucEncData)+1] = 1;
			result[5+strlen(pucEncData)+2] = strlen(pucEncData);
			
			break;
		}
		case SDF_Decrypt:
		{
			unsigned char *key = (unsigned int *)malloc(1024);
			unsigned char *pucIV = (unsigned int *)malloc(1024);
			unsigned char *pucData = (unsigned int *)malloc(1024);
			int keylength = (int)params[4];
			memcpy(key,params+5,keylength);
			int uiAlgID = (int)params[5+keylength+1];
			int IVlength = (int)params[5+keylength+2];
			memcpy(pucIV,params+5+keylength+3,IVlength);
			int pucdatalength = (int)params[5+keylength+3+IVlength+1];
			memcpy(pucData,params+5+keylength+3+IVlength+2,pucdatalength);
			unsigned char *pucEncData = (unsigned int *)malloc(1024);
			ALG_SDF_Decrypt(key,uiAlgID,pucIV,pucData,pucdatalength,pucEncData);
			
			int outdatalength = strlen(pucEncData);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = strlen(pucEncData);
			memcpy((result+5),pucEncData,strlen(pucEncData));
			result[5+strlen(pucEncData)+1] = 1;
			result[5+strlen(pucEncData)+2] = strlen(pucEncData);
			break;			
		}
		case SDF_CalculateMAC:
		{
			unsigned char *key = (unsigned int *)malloc(1024);
			int keylength = params[4];
			memcpy(key,params+5,keylength);
			unsigned char *text = (unsigned int *)malloc(1024);
			int textlen = params[5+keylength];
			memcpy(text,params+5+keylength+1,textlen);
			unsigned char *hmac = (unsigned int *)malloc(1024);
			
			ALG_SDF_CalculateMAC(key,keylength,text,textlen, hmac);
			
			result[0] = params[0];
			result[2] = params[2];
			result[4] = strlen(hmac);
			memcpy((result+5),hmac,32);
			result[5+32] = 1;
			result[5+32+1] = 32;
			break;
		}
	}
}
