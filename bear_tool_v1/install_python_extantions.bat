#!/bin/bash

if ! command -v pip &> /dev/null
then
    echo "pip not found. Installing pip..."
    sudo apt update
    sudo apt install -y python3-pip
fi

echo "Installing required packages..."
pip3 install --upgrade pip
pip3 install scapy requests paramiko colorama ftplib

echo "Verifying package installation..."
pip3 list | grep -E 'scapy|requests|paramiko|colorama|ftplib'

echo "Packages installed successfully!"

echo "You can now run your tool!"