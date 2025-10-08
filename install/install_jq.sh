#!/bin/bash

function install_jq() {
  echo 'Installing jq globally...'
  if [[ $EUID -eq 0 ]]; then
    apt install -y jq 
  elif sudo -n true 2>/dev/null; then
    sudo apt install -y jq
  else
    echo "Error: You need to run this script as root or a user with sudo privileges."
    exit 1
  fi
}

# Check if jq is installed
if command -v jq >/dev/null 2>&1; then
  echo "jq is already installed."
else
  install_jq
fi