echo "#ifndef MIRDEF_H_20121220       "   >  mirdef.h
echo "#define MIRDEF_H_20121220       "   >> mirdef.h
echo "" >> mirdef.h
echo "#define MR_LITTLE_ENDIAN                  " >> mirdef.h
echo "#define MIRACL 32                         " >> mirdef.h
echo "#define mr_utype int                      " >> mirdef.h
echo "#define MR_IBITS 32                       " >> mirdef.h
echo "#define MR_LBITS 32                       " >> mirdef.h
echo "#define mr_unsign32 unsigned int          " >> mirdef.h
echo "#define mr_dltype long long               " >> mirdef.h
echo "#define mr_unsign64 unsigned long long    " >> mirdef.h
echo "//#define MR_NOASM                          " >> mirdef.h
echo "#define MR_FLASH 52                       " >> mirdef.h
echo "#define MR_STRIPPED_DOWN                  " >> mirdef.h
echo "#define MR_GENERIC_MT                     " >> mirdef.h
echo "#define MR_NO_STANDARD_IO                 " >> mirdef.h
echo "#define MR_NO_FILE_IO                     " >> mirdef.h
echo "#define MR_ALWAYS_BINARY                  " >> mirdef.h
echo "#define MR_COMBA 8                        " >> mirdef.h
echo "#define MAXBASE ((mr_small)1<<(MIRACL-1)) " >> mirdef.h
echo "#define MR_BITSINCHAR 8                   " >> mirdef.h
echo "//#define MR_COMBA2   8                     " >> mirdef.h
echo "//#define MR_KCM      8                     " >> mirdef.h
echo "#define MR_STATIC     16                  " >> mirdef.h

echo "#//define MR_SPECIAL                  " >> mirdef.h
echo "#//define MR_GENERALIZED_MERSENNE     " >> mirdef.h
echo "#//define MR_PSEUDO_MERSENNE     " >> mirdef.h
echo "#//define MR_NO_LAZY_REDUCTION     " >> mirdef.h
echo "#endif                                    " >> mirdef.h

echo "" >> mirdef.h


rm *.exe
rm miracl.a
#cp mirdef.x86_32 mirdef.h
#cp ../mirdef.tst mirdef.h

echo ""
gcc -o mex mex.c
./mex 8 gccsse2 mrcomba
#./mex 8 gccsse2 mrcomba2
#./mex 8 gccsse2 mrkcm
gcc -c -m32 -O2 mrcore.c
gcc -c -m32 -O2 mrarth0.c
gcc -c -m32 -O2 mrarth1.c
gcc -c -m32 -O2 mrarth2.c
gcc -c -m32 -O2 mralloc.c
gcc -c -m32 -O2 mrsmall.c
gcc -c -m32 -O2 mrio1.c
gcc -c -m32 -O2 mrio2.c
gcc -c -m32 -O2 mrgcd.c
gcc -c -m32 -O2 mrjack.c
gcc -c -m32 -O2 mrxgcd.c
gcc -c -m32 -O2 mrarth3.c
gcc -c -m32 -O2 mrbits.c
gcc -c -m32 -O2 mrrand.c
gcc -c -m32 -O2 mrprime.c
gcc -c -m32 -O2 mrcrt.c
gcc -c -m32 -O2 mrscrt.c
gcc -c -m32 -O2 mrmonty.c
gcc -c -m32 -O2 mrpower.c
gcc -c -m32 -O2 mrsroot.c
gcc -c -m32 -O2 mrcurve.c
gcc -c -m32 -O2 mrfast.c
gcc -c -m32 -O2 mrshs.c
gcc -c -m32 -O2 mrshs256.c
gcc -c -m32 -O2 mrshs512.c
gcc -c -m32 -O2 mraes.c
gcc -c -m32 -O2 mrgcm.c
gcc -c -m32 -O2 mrlucas.c
gcc -c -m32 -O2 mrzzn2.c
gcc -c -m32 -O2 mrzzn2b.c
gcc -c -m32 -O2 mrzzn3.c
gcc -c -m32 -O2 mrzzn4.c
gcc -c -m32 -O2 mrecn2.c
gcc -c -m32 -O2 mrstrong.c
gcc -c -m32 -O2 mrbrick.c
gcc -c -m32 -O2 mrebrick.c
gcc -c -m32 -O2 mrec2m.c
gcc -c -m32 -O2 mrgf2m.c
gcc -c -m32 -O2 mrflash.c
gcc -c -m32 -O2 mrfrnd.c
gcc -c -m32 -O2 mrdouble.c
gcc -c -m32 -O2 mrround.c
gcc -c -m32 -O2 mrbuild.c
gcc -c -m32 -O2 mrflsh1.c
gcc -c -m32 -O2 mrpi.c
gcc -c -m32 -O2 mrflsh2.c
gcc -c -m32 -O2 mrflsh3.c
gcc -c -m32 -O2 mrflsh4.c
gcc -c -m32 -O2 sm2.c
gcc -c -m32 -O2 sm3.c
gcc -c -m32 -O2 sm4.c
gcc -c -m32 -msse2 -O2 mrcomba.c
#gcc -c -m32 -msse2 -O2 mrcomba2.c
#gcc -c -m32 -msse2 -O2 mrkcm.c
cp mrmuldv.gcc mrmuldv.c
gcc -c -m32 -O2 mrmuldv.c
ar rc miracl.a mrcore.o mrarth0.o mrarth1.o mrarth2.o mralloc.o mrsmall.o mrzzn2.o mrzzn3.o
ar r miracl.a mrio1.o mrio2.o mrjack.o mrgcd.o mrxgcd.o mrarth3.o mrbits.o mrecn2.o mrzzn4.o
ar r miracl.a mrrand.o mrprime.o mrcrt.o mrscrt.o mrmonty.o mrcurve.o mrsroot.o mrzzn2b.o
ar r miracl.a mrpower.o mrfast.o mrshs.o mrshs256.o mraes.o mrlucas.o mrstrong.o mrgcm.o     
ar r miracl.a mrflash.o mrfrnd.o mrdouble.o mrround.o mrbuild.o
ar r miracl.a mrflsh1.o mrpi.o mrflsh2.o mrflsh3.o mrflsh4.o 
ar r miracl.a mrbrick.o mrebrick.o mrec2m.o mrgf2m.o mrmuldv.o mrshs512.o
ar r miracl.a mrcomba.o 
#ar r miracl.a mrcomba2.o
#ar r miracl.a mrkcm.o
ar r miracl.a sm2.o sm3.o sm4.o

rm mr*.o
rm sm*.o
