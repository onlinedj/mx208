#!/bin/sh

#set -x

SOURCE_DIR=`pwd`
BUILD_DIR=${BUILD_DIR:-build}
BUILD_TYPE=${BUILD_TYPE:-debug}
BUILD_NO_TEST=${BUILD_NO_TEST:-0}

mkdir -p $BUILD_DIR/$BUILD_TYPE \
  && cd $BUILD_DIR/$BUILD_TYPE \
  && cmake \
           -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
           -DCMAKE_BUILD_NO_TEST=$BUILD_NO_TEST \
           $SOURCE_DIR \
  && make $*

#TODO use doxygen create document.
# cd $SOURCE_DIR && doxygen

