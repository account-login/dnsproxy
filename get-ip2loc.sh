#!/usr/bin/env bash

rm -rv IP2LOCATION-LITE-DB1.CSV.ZIP
wget https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP
unzip -p IP2LOCATION-LITE-DB1.CSV IP2LOCATION-LITE-DB1.CSV |python3 ip2loc_gen.py
