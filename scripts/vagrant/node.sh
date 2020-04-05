#!/usr/bin/env bash

# Installs nvm node and global packages

source /vagrant/scripts/vagrant/common.env

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash

# source $HOME/.bashrc
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm

nvm install 10

npm install --global mocha
