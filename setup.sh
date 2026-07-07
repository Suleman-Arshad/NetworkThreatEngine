#!/bin/bash
echo "Installing dependencies for Network Threat Engine..."
sudo apt update
sudo apt install build-essential cmake libpcap-dev -y
sudo apt install libsqlite3-dev sqlite3
echo "All dependencies installed successfully!"