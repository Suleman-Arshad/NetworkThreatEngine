#!/bin/bash
echo "Installing dependencies for Network Threat Engine..."
sudo apt update
sudo apt install build-essential cmake libpcap-dev -y
sudo apt install libsqlite3-dev sqlite3
sudo apt-get install libncurses-dev
echo "All dependencies installed successfully!"