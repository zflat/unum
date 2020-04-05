#!/usr/bin/env bash

initial_dir="$(pwd -P)"

source /vagrant/scripts/vagrant/common.env

if [[ ! -d "$HOME/redis-stable" ]] ; then
    cd $HOME && wget http://download.redis.io/releases/redis-stable.tar.gz
    tar -xzf redis-stable.tar.gz
    cd redis-stable
    make && \
    REDIS_VERSION=`src/redis-cli --version | awk '{print $2}'` && \
    sudo checkinstall -y --pkgversion=$REDIS_VERSION --pkgsource=$HOME/redis-stable/src make install
fi

# Build APP in /home/vagrant on Linux filesystem,
# outside /vagrant which is VM shared directory.
# Otherwise, CMake will fail:
# CMake Error: cmake_symlink_library: System Error: Protocol error
# Explanation from https://github.com/mitchellh/vagrant/issues/713
# The VirtualBox shared folder filesystem doesn't allow symlinks, unfortunately.
# Your only option is to deploy outside of the shared folders.
if [[ ! -d "${SOCI_HOME}" ]] ; then
  mkdir -p ${SOCI_HOME}
  git clone https://github.com/SOCI/soci.git ${SOCI_HOME}
  mkdir -p ${SOCI_BUILD}

  # Builds and tests from git master branch
  echo "Build: building APP from sources in ${APP_HOME} to build in ${SOCI_BUILD}"
  cd ${SOCI_BUILD} && \
      cmake \
          -DSOCI_CXX_C11=ON \
          -DSOCI_CXX11=ON \
          -DSOCI_TESTS=ON \
          -DSOCI_STATIC=ON \
          -DSOCI_SHARED=OFF \
          -DSOCI_DB2=OFF \
          -DSOCI_ODBC=OFF \
          -DSOCI_ORACLE=OFF \
          -DSOCI_EMPTY=OFF \
          -DSOCI_FIREBIRD=OFF \
          -DSOCI_MYSQL=ON \
          -DSOCI_POSTGRESQL=OFF \
          -DSOCI_SQLITE3=ON \
          -DSOCI_MYSQL_TEST_CONNSTR:STRING="host=localhost db=${APP_USER} user=${APP_USER} password=${APP_PASS}" \
          ${SOCI_HOME} && \
      make && \
      sudo checkinstall --pkgname soci -y make install
fi

if [ ! -d "${APP_BUILD}" ] ; then
  mkdir -p ${APP_BUILD}
  cd ${APP_BUILD} && \
  cmake ${APP_HOME} && \
  make
  echo "Build: building DONE"
  # Do not run tests during provisioning, they may fail terribly, so just build
  # and let to run them manually after developer vagrant ssh'ed to the VM.
  echo "Build: ready to test APP by running: cd ${APP_BUILD}; ctest -V --output-on-failure ."
else
    cd ${APP_BUILD} && make
fi

cd $initial_dir
