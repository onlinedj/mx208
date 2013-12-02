/* 
 *   MIRACL compiler/hardware definitions - mirdef.h
 *   This version suitable for use with most 32-bit computers
 *   e.g. 80386+ PC, VAX, ARM etc. Assembly language versions of muldiv,
 *   muldvm, muldvd and muldvd2 will be necessary. See mrmuldv.any 
 *
 *   Suitable for Unix/Linux and for DJGPP GNU C Compiler
 *   Copyright (c) 1988-2006 Shamus Software Ltd.
 */


#if 0

#define MR_LITTLE_ENDIAN
#define MIRACL 32
#define mr_utype int
#define MR_IBITS 32
#define MR_LBITS 32
#define mr_unsign32 unsigned int
#define MR_FLASH 52
#define MR_STRIPPED_DOWN
#define MR_GENERIC_MT
#define MR_NO_STANDARD_IO
#define MR_ALWAYS_BINARY
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_KCM 8
#define MR_BITSINCHAR 8

#else

/*#define MR_BIG_ENDIAN*/    /* This may need to be changed        */
#define MR_LITTLE_ENDIAN    /* This may need to be changed        */
#define MIRACL 32
#define mr_utype int
                            /* the underlying type is usually int *
                             * but see mrmuldv.any                */
#define mr_unsign32 unsigned int
                            /* 32 bit unsigned type               */
#define MR_IBITS      32    /* bits in int  */
#define MR_LBITS      32    /* bits in long */
#define MR_FLASH      52      
                            /* delete this definition if integer  *
                             * only version of MIRACL required    */
                            /* Number of bits per double mantissa */

#define mr_dltype long long   /* ... or __int64 for Windows       */
#define mr_unsign64 unsigned long long

#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MRBITSINCHAR 8 
//#define MR_KCM 16
#define MR_COMBA 8
//#define MR_NOASM 
#define MR_NO_STANDARD_IO /* no printf support */
#define MR_GENERIC_MT   /* multi-threaded */
#define MR_STRIPPED_DOWN
#define MR_ALWAYS_BINARY

#endif
