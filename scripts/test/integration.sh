#!/usr/bin/env bash

initial_dir="$(pwd -P)"
integration_sh_dir="$(dirname "$0")"

source "$integration_sh_dir/../vagrant/common.env"

if [ "$1" = "build" ]; then
   source "$integration_sh_dir/../vagrant/build.sh"
fi

if [[ -z "${DB_TEST_USER}" ]]; then
    DB_TEST_USER=$APP_USER_TEST
fi
if [[ -z "${DB_TEST_NAME}" ]]; then
    DB_TEST_NAME=$APP_USER_TEST
fi
if [[ -z "${DB_TEST_PASS}" ]]; then
    DB_TEST_PASS=$APP_PASS
fi

source "$integration_sh_dir/setup.sh"
source "$integration_sh_dir/seed.sh"

set -e

binary_name="app.fcgi"
if [[ ! -e "/var/www/app/${binary_name}" ]]; then
    echo "Establish link"
    sudo ln -sf "${APP_BUILD}/${binary_name}" "/var/www/app/${binary_name}"
else
    # trigger apache2 to restart fcgi processes by modifying the (symlink)
    # executable timestamps
    sudo touch /var/www/app*.fcgi
    sudo touch -h /var/www/app*.fcgi
fi


cd "$integration_sh_dir/../../tests/integration"
mocha

cd $initial_dir
