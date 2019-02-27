if [ ! -d build ] ; then
  mkdir build
fi
cd build

cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..
ninja