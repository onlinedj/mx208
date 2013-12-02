rm *.exe
rm miracl.a

cp mirdef_x86.h64 mirdef.h

#### FAIL at compile on i7 ####
#./mex 4 gccsse2 mrcomba
#./mex 4 sse2 mrcomba

#### FAIL at run  on i7 ####
#./mex 4 clmul mrcomba
#./mex 4 gcclmul mrcomba


##### OK on i7 #####
./mex 4 amd64 mrcomba
#./mex 4 amd64 mrcomba2

gcc -c -m64  -O3 mrcore.c
gcc -c -m64  -O3 mrarth0.c
gcc -c -m64  -O3 mrarth1.c
gcc -c -m64  -O3 mrarth2.c
gcc -c -m64  -O3 mralloc.c
gcc -c -m64  -O3 mrsmall.c
gcc -c -m64  -O3 mrio1.c
gcc -c -m64  -O3 mrio2.c
gcc -c -m64  -O3 mrgcd.c
gcc -c -m64  -O3 mrjack.c
gcc -c -m64  -O3 mrxgcd.c
gcc -c -m64  -O3 mrarth3.c
gcc -c -m64  -O3 mrbits.c
gcc -c -m64  -O3 mrrand.c
gcc -c -m64  -O3 mrprime.c
gcc -c -m64  -O3 mrcrt.c
gcc -c -m64  -O3 mrscrt.c
gcc -c -m64  -O3 mrmonty.c
gcc -c -m64  -O3 mrpower.c
gcc -c -m64  -O3 mrsroot.c
gcc -c -m64  -O3 mrcurve.c
gcc -c -m64  -O3 mrfast.c
gcc -c -m64  -O3 mrshs.c
gcc -c -m64  -O3 mrshs256.c
gcc -c -m64  -O3 mrshs512.c
gcc -c -m64  -O3 mraes.c
gcc -c -m64  -O3 mrgcm.c
gcc -c -m64  -O3 mrlucas.c
gcc -c -m64  -O3 mrzzn2.c
gcc -c -m64  -O3 mrzzn2b.c
gcc -c -m64  -O3 mrzzn3.c
gcc -c -m64  -O3 mrzzn4.c
gcc -c -m64  -O3 mrecn2.c
gcc -c -m64  -O3 mrstrong.c
gcc -c -m64  -O3 mrbrick.c
gcc -c -m64  -O3 mrebrick.c
gcc -c -m64  -O3 mrec2m.c
gcc -c -m64  -O3 mrgf2m.c
gcc -c -m64  -O3 mrflash.c
gcc -c -m64  -O3 mrfrnd.c
gcc -c -m64  -O3 mrdouble.c
gcc -c -m64  -O3 mrround.c
gcc -c -m64  -O3 mrbuild.c
gcc -c -m64  -O3 mrflsh1.c
gcc -c -m64  -O3 mrpi.c
gcc -c -m64  -O3 mrflsh2.c
gcc -c -m64  -O3 mrflsh3.c
gcc -c -m64  -O3 mrflsh4.c
gcc -c -m64  -O3 mrcomba.c
#gcc -c -m64  -O3 mrcomba2.c
#gcc -c -m64  -O3 mrkcm.c
gcc -c -m64  -O3 sm2.c
gcc -c -m64  -O3 sm3.c
gcc -c -m64  -O3 sm4.c

#cp mrmuldv.g64 mrmuldv.c
#gcc -c -m64  -O2 mrmuldv.c
as mrmuldv.s64 -o mrmuldv.o

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
