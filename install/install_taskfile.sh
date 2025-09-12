#!/bin/bash

function install_taskfile() {
  echo 'Installing Taskfile globally...'

  if [[ $EUID -eq 0 ]]; then
    # Run directly as root
    curl -sSL https://taskfile.dev/install.sh | bash -s -- -d /usr/local/bin
  elif sudo -n true 2>/dev/null; then
    # Run with sudo (non-interactive check passed)
    curl -sSL https://taskfile.dev/install.sh | sudo bash -s -- -d /usr/local/bin
  else
    echo "Error: You need to run this script as root or a user with sudo privileges." >&2
    exit 1
  fi
}

# Check if Taskfile is installed
if command -v task >/dev/null 2>&1 && task --version >/dev/null 2>&1; then
  echo "Taskfile is already installed."
else
  install_taskfile
fi
