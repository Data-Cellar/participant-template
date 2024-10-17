#!/bin/bash

function install_taskfile() {
  echo 'Installing Taskfile globally...'
  curl --location https://taskfile.dev/install.sh | sudo bash -s -- -d /usr/local/bin
}

if [[ $(which task) && $(task --version) ]]; then
  echo "Taskfile is already installed."
else
  install_taskfile
fi