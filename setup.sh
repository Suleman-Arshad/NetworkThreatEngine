#!/bin/bash
echo "Installing dependencies for Network Threat Engine..."
sudo apt update
sudo apt install build-essential cmake libpcap-dev -y
echo "All dependencies installed successfully!"