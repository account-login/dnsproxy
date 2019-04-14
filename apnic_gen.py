#!/usr/bin/env python3

import sys
import json
from ipaddress import ip_address


def main():
    iplist = []
    for line in sys.stdin:
        ips, size = line.split()
        ip_start = int(ip_address(ips))
        ip_stop = ip_start + int(size)

        iplist.append((ip_start, ip_stop))

    iplist.sort()

    print(
'''package dnsproxy

import (
	"encoding/binary"
	"net"
	"sort"
)

var cnList [][2]uint32

func init() {
	cnList = [][2]uint32{''')

    for s, e in iplist:
        print('\t\t{%d, %d},' % (s, e))

    print(
'''	}
}

func isCNIPV4(ip net.IP) bool {
	if len(ip) != 4 {
		panic("not ipv4")
	}
	n := binary.BigEndian.Uint32(ip)
	i := sort.Search(len(cnList), func(i int) bool {
		return cnList[i][1] > n
	})
	return i < len(cnList) && n >= cnList[i][0]
}''')


if __name__ == '__main__':
    main()
