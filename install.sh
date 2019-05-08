#!/bin/bash

apt-get update

apt-get -y install python3-pip
apt-get -y install python3-selenium
apt-get -y install chromium-driver
apt-get -y install sqlite3

# Install nMap Merger
git clone https://github.com/CBHue/nMap_Merger.git /opt/nMap_Merger
