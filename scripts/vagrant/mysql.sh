#!/usr/bin/env bash

# Installs MySQL with 'soci' user and database
# Pre-installation
source /vagrant/scripts/vagrant/common.env
export DEBIAN_FRONTEND="noninteractive"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password password ${APP_PASS}"
sudo debconf-set-selections <<< "mysql-server mysql-server/root_password_again password ${APP_PASS}"
# Installation
sudo apt-get -o Dpkg::Options::='--force-confnew' -y -q install \
  mysql-server
# Post-installation
echo "MySQL: updating /etc/mysql/my.cnf"
sudo sed -i "s/bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/my.cnf
echo "MySQL: setting root password to ${APP_PASS}"
mysql -uroot -p${APP_PASS} -e \
  "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${APP_PASS}' WITH GRANT OPTION; FLUSH PRIVILEGES;"
echo "MySQL: creating user ${APP_USER}"
mysql -uroot -p${APP_PASS} -e \
  "GRANT ALL PRIVILEGES ON ${APP_USER}.* TO '${APP_USER}'@'%' IDENTIFIED BY '${APP_PASS}' WITH GRANT OPTION"
mysql -uroot -p${APP_PASS} -e "DROP DATABASE IF EXISTS ${APP_USER}"
echo "MySQL: creating database ${APP_USER}"
mysql -uroot -p${APP_PASS} -e "CREATE DATABASE ${APP_USER}"
echo "MySQL: restarting"
sudo service mysql restart
if [[ ! -d "$HOME/.my.cnf" ]] ; then
    echo "[client]" >> "$HOME/.my.cnf"
    echo "password=$APP_PASS" >> "$HOME/.my.cnf"
fi
echo "MySQL: DONE"

