#!/usr/bin/env bash

rm -fv delegated-apnic-extended-latest
curl https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest >delegated-apnic-extended-latest
cat delegated-apnic-extended-latest |grep ipv4 |grep CN |grep -P 'allocated|assigned' \
    |awk -F'|' '{print $4, $5}' >cn.txt
