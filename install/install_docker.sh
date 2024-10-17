#!/bin/bash


function install_docker() {
  echo 'Installing Docker '
  
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo chmod +x ./get-docker.sh
  sudo sh ./get-docker.sh --dry-run
  
  sudo usermod -aG docker ${USER}

  sudo systemctl enable docker.service
  sudo systemctl enable containerd.service
}

if [[ $(which docker) && $(docker --version) ]]; then
    echo "Docker installed"
  else
    install_docker;
fi