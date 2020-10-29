import sys
import csv


# https://download.ip2location.com/lite/IP2LOCATION-LITE-DB1.CSV.ZIP
# unzip -p IP2LOCATION-LITE-DB1.CSV IP2LOCATION-LITE-DB1.CSV |python3 ip2loc_gen.py >cn_list.go
def main():
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
    # "16777216","16777471","US","United States of America"
    reader = csv.reader(sys.stdin)
    items = []
    for s, e, country, *_ in reader:
        if country == 'CN':
            items.append((int(s), int(e) + 1))

    items.sort()

    for s, e in items:
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


if __name__ == "__main__":
    main()
