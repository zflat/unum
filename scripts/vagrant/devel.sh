#!/usr/bin/env bash
#
# Installs essentials and core dependencies
# Pre-installation
source /vagrant/scripts/vagrant/common.env
export DEBIAN_FRONTEND="noninteractive"
sudo apt-get install -y software-properties-common
#sudo add-apt-repository ppa:george-edison55/cmake-3.x
sudo apt-get update -y -q
# Installation
sudo apt-get -o Dpkg::Options::='--force-confnew' -y -q install \
  build-essential \
  git \
  checkinstall\
  libmyodbc \
  libmysqlclient-dev \
  libsqlite3-dev \
  libcurl4-openssl-dev \
  libfcgi-dev\
  libhiredis-dev\
  valgrind
#  cmake \
#  libboost-dev \
#  libboost-date-time-dev \

# Update cmake
# https://askubuntu.com/a/595441
cd $HOME
if [[ ! -d cmake-3.7.2 ]] ; then
    sudo apt-get remove --purge cmake
    wget https://cmake.org/files/v3.7/cmake-3.7.2.tar.gz
    tar -xzf cmake-3.7.2.tar.gz
    cd cmake-3.7.2
    ./bootstrap
    make -j4
    sudo checkinstall -y make install
fi

# Post-installation
cd $HOME
