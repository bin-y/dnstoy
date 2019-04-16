#!/bin/bash
if [ ! -d build/debug ] ; then
  mkdir -p build/debug
fi
cd build/debug

cmake -DCMAKE_BUILD_TYPE=Debug -G Ninja ../..
ninja