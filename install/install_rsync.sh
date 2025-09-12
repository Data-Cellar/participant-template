#!/bin/bash

function install_rsync() {
  echo 'Installing rsync globally...'
  if [[ $EUID -eq 0 ]]; then
    apt install -y rsync 
  elif sudo -n true 2>/dev/null; then
    sudo apt install -y rsync
  else
    echo "Error: You need to run this script as root or a user with sudo privileges."
    exit 1
  fi
}

# Check if rsync is installed
if command -v rsync >/dev/null 2>&1; then
  echo "rsync is already installed."
else
  install_rsync
fi