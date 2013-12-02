set(sm_SRCS
mrmuldv.s
mrcore.c
mrarth0.c
mrarth1.c
mrarth2.c
mralloc.c
mrsmall.c
mrio1.c
mrio2.c
mrgcd.c
mrjack.c
mrxgcd.c
mrarth3.c
mrbits.c
mrrand.c
mrprime.c
mrcrt.c
mrscrt.c
mrmonty.c
mrpower.c
mrsroot.c
mrcurve.c
mrfast.c
mrshs.c
mrshs256.c
mrshs512.c
mraes.c
mrgcm.c
mrlucas.c
mrzzn2.c
mrzzn2b.c
mrzzn3.c
mrzzn4.c
mrecn2.c
mrstrong.c
mrbrick.c
mrebrick.c
mrec2m.c
mrgf2m.c
mrflash.c
mrfrnd.c
mrdouble.c
mrround.c
mrbuild.c
mrflsh1.c
mrpi.c
mrflsh2.c
mrflsh3.c
mrflsh4.c
mrcomba.c
mrcomba2.c
sm2.c
sm3.c
sm4.c
)

set(asm_SRCS
mrmuldv.s
    )

set_source_files_properties(asm_SRCS PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")

add_library(sm SHARED ${sm_SRCS})
target_link_libraries(sm m)
