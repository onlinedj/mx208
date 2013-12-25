cmake_minimum_required(VERSION 2.8)

project(MXSERVER C ASM)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "debug")
endif()

set(C_FLAGS
 -m64
 #-g
 #-Wall
 #-Wunused-variable
 #-Wextra
 #-Werror
 #-Wconversion
 #-Wno-unused-parameter
 #-Wpointer-arith
 )

#if(CMAKE_BUILD_BITS EQUAL 32)
#  list(APPEND C_FLAGS "-m32")
#endif()

string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_FLAGS_DEBUG "-O0")
set(CMAKE_C_FLAGS_RELEASE "-O2 -finline-limit=1000 -DNDEBUG")
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "C_FLAGS = " ${CMAKE_C_FLAGS} " " ${CMAKE_C_FLAGS_${BUILD_TYPE}})

include_directories(include)
include_directories(sm2_3_4)
add_subdirectory(sm2_3_4)
add_subdirectory(src)

if(NOT CMAKE_BUILD_NO_TEST)
  add_subdirectory(test)
endif()

