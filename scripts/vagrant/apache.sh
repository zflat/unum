#!/usr/bin/env bash

# Install apache (and configures for testing)
source /vagrant/scripts/vagrant/common.env

sudo apt-get update -y -q
sudo apt-get -o Dpkg::Options::='--force-confnew' -y -q install \
     apache2 \
     libapache2-mod-fcgid

sudo a2enmod rewrite
sudo a2enmod fcgid

sudo rm /etc/apache2/sites-enabled/*.conf
sudo cp /vagrant/scripts/vagrant/sites-available-default.conf /etc/apache2/sites-available/test-default.conf
sudo mkdir -p /var/www/app
sudo ln -sf /etc/apache2/sites-available/test-default.conf /etc/apache2/sites-enabled/default.conf

# set up the (test) application
sudo cp /vagrant/scripts/vagrant/.htaccess /var/www/app
sudo sed -i -i "s/valDbName/$APP_USER_TEST/g" /var/www/app/.htaccess
sudo sed -i -i "s/valDbUser/$APP_USER_TEST/g" /var/www/app/.htaccess
sudo sed -i -i "s/valDbPw/$APP_PASS/g"        /var/www/app/.htaccess
sudo sed -i -i "s/valDbHost/127.0.0.1/g"      /var/www/app/.htaccess

sudo service apache2 restart

# apache2 -l
# sudo apache2ctl -M
