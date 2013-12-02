#include "algorithm_manager.h"

#include "commands.h"


int process_command_algorithm(uint8_t *params, uint8_t *result)
{
    uint32_t *tmp = (uint32_t *) params;
    uint32_t command = tmp[0];
    printf("command=%8x\n",command);
    int total = 0;
    switch(command)
    {
    case SDF_ENCRYPT:
        {
            /*uint32_t alg_id = *(tmp+8);*/
            uint32_t key_s = *(tmp+5);
            uint32_t *tmp32 = (uint32_t*)(params+24+key_s+8);
            uint32_t puciv_s = *tmp32;
            tmp32 = (uint32_t*)(params+24+key_s);
            uint32_t algid_s = *tmp32;
            uint32_t algid = *(tmp32+1);
            tmp32 = (uint32_t*)(params+24+key_s+8+4+puciv_s);
            printf("in algo buffer=%d,%d,%d,%d,%d,%d,%d\n",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5],tmp[6]);
            uint32_t data_size = *tmp32;
            printf("key_s=%d,algid_s=%d,algid=%d,puciv_s=%d,data_size=%d\n",key_s,algid_s,algid,puciv_s,data_size);
            uint8_t data[65536];
            if(data_size< 65536)
            {
                memcpy(data,params+24+key_s+8+4+puciv_s+4,data_size);	

            }
            /*int key_size ;
            uint32_t *ktmp = (uint32_t *)(params+24+data_size);
            key_size = *ktmp;
            uint8_t key[65536];
            if(key_size < 65536)
            {
                memcpy(key,params+28+data_size,key_size);
            }*/
            uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
            int i ;
            for(i =0; i<16;i++)
            {
                printf("%2X",data[i]);
            }
            printf("\n");
            for(i =0; i<16;i++)
            {
                printf("%2X",key[i]);
            }
            printf("\n");

            unsigned char outs[16];
            alo_ECBencrpyt(data,outs,data_size,key,1); 		
            int allbytes = params+24+key_s+8+puciv_s+4+data_size+8;
            uint32_t my[4] = {SDF_ENCRYPT,44,2,0};
            memcpy(result,my,sizeof(uint32_t)*4);
            int out_size = data_size;
            uint32_t param_size = 4;
            memcpy(result+sizeof(uint32_t)*4,&out_size,sizeof(uint32_t));
            memcpy(result+sizeof(uint32_t)*5,outs,out_size);
            memcpy(result+sizeof(uint32_t)*5+out_size,&param_size,4);
            memcpy(result+sizeof(uint32_t)*5+out_size+4,&out_size,4);
            printf("encrypt result:%d,%d\n",out_size,16);
            for(i =0; i<16;i++)
            {
                printf("%2X",outs[i]);
            }
            printf("\n");
            total = 44;

            break;
        }
    case SDF_DECRYPT:
        {
            /*uint32_t alg_id = *(tmp+8);*/
            uint32_t key_s = *(tmp+5);
            uint32_t *tmp32 = (uint32_t*)(params+24+key_s+8);
            uint32_t puciv_s = *tmp32;
            tmp32 = (uint32_t*)(params+24+key_s+8+4+puciv_s);
            printf("in algo buffer=%d,%d,%d,%d,%d,%d,%d\n",tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5],tmp[6]);
            uint32_t data_size = *tmp32;
            printf("key_s=%d,puciv_s=%d,data_size=%d\n",key_s,puciv_s,data_size);
            uint8_t data[65536];
            if(data_size< 65536)
            {
                memcpy(data,params+24+key_s+8+4+puciv_s+4,data_size);	

            }
            /*int key_size ;
            uint32_t *ktmp = (uint32_t *)(params+24+data_size);
            key_size = *ktmp;
            uint8_t key[65536];
            if(key_size < 65536)
            {
                memcpy(key,params+28+data_size,key_size);
            }*/
            uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
            int i ;
            for(i =0; i<16;i++)
            {
                printf("%2X",data[i]);
            }
            printf("\n");
            for(i =0; i<16;i++)
            {
                printf("%2X",key[i]);
            }
            printf("\n");

            unsigned char outs[16];
            alo_ECBencrpyt(data,outs,data_size,key,0); 		
            uint32_t my[4] = {SDF_ENCRYPT,44,2,0};
            memcpy(result,my,sizeof(uint32_t)*4);
            int out_size = data_size;
            uint32_t param_size = 4;
            memcpy(result+sizeof(uint32_t)*4,&out_size,sizeof(uint32_t));
            memcpy(result+sizeof(uint32_t)*5,outs,out_size);
            memcpy(result+sizeof(uint32_t)*5+out_size,&param_size,4);
            memcpy(result+sizeof(uint32_t)*5+out_size+4,&out_size,4);
            printf("encrypt result:%d,%d\n",out_size,16);
            for(i =0; i<16;i++)
            {
                printf("%2X",outs[i]);
            }
            printf("\n");
            total = 44;

            break;
        }
    default:

        break;
    } 
    return total;
    
}
