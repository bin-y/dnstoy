cd libs
apt-get install libssl-dev

if [ -z $DNSTOY_BUILD_CONCURRENCY ]; then
  DNSTOY_BUILD_CONCURRENCY=2
fi

# ---- begin code copied and modified from carla Simulator which is MIT License
# ==============================================================================
# -- Get boost includes --------------------------------------------------------
# ==============================================================================

BOOST_VERSION=1.69.0
BOOST_BASENAME="boost-${BOOST_VERSION}"

if [[ -d "${BOOST_BASENAME}-install" ]] ; then
  echo "${BOOST_BASENAME} already installed."
else
  if [ ! -d "${BOOST_BASENAME}-source" ]; then
    if [ ! -f "boost_${BOOST_VERSION//./_}.tar.gz" ] ; then
      echo "Downloading boost."
      wget "https://dl.bintray.com/boostorg/release/${BOOST_VERSION}/source/boost_${BOOST_VERSION//./_}.tar.gz"
    fi
    echo "Extracting boost."
    tar -xzf ${BOOST_BASENAME//[-.]/_}.tar.gz
    mkdir -p ${BOOST_BASENAME}-install/include
    mv ${BOOST_BASENAME//[-.]/_} ${BOOST_BASENAME}-source
  fi
  pushd ${BOOST_BASENAME}-source >/dev/null

  if [ ! -f "b2" ] ; then
    ./bootstrap.sh --prefix="../${BOOST_BASENAME}-install"
  fi

  BOOST_CXXFLAGS="-I . -std=c++17"

  ./b2 cxxflags="${BOOST_CXXFLAGS}" -j ${DNSTOY_BUILD_CONCURRENCY} stage release
  ./b2 -j ${DNSTOY_BUILD_CONCURRENCY} install
  ./b2 -j ${DNSTOY_BUILD_CONCURRENCY} --clean-all

  # Get rid of  python2 build artifacts completely & do a clean build for python3
  popd >/dev/null
  rm -Rf ${BOOST_BASENAME}-source
  rm ${BOOST_BASENAME//[-.]/_}.tar.gz

fi

unset BOOST_BASENAME
# ---- end code copied and modified from carla Simulator which is MIT License