#!/bin/bash

function install_rsync() {
  echo 'Installing rsync globally...'
  sudo apt install -y rsync
}

if [[ $(which rsync) && $(rsync --version) ]]; then
  echo "rsync is already installed."
else
  install_rsync
fi