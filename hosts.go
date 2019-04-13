// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsproxy

import (
	"bufio"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const cacheMaxAge = 5 * time.Second

func parseLiteralIP(addr string) string {
	var ip net.IP
	ip = net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// hosts contains known host entries.
var hosts struct {
	sync.Mutex

	// Key for the list of literal IP addresses must be a host
	// name. It would be part of DNS labels, a FQDN or an absolute
	// FQDN.
	// For now the key is converted to lower case for convenience.
	byName map[string][]string

	// Key for the list of host names must be a literal IP address
	// including IPv6 address with zone identifier.
	// We don't support old-classful IP address notation.
	byAddr map[string][]string

	expire time.Time
	path   string
	mtime  time.Time
	size   int64
}

func stat(name string) (mtime time.Time, size int64, err error) {
	st, err := os.Stat(name)
	if err != nil {
		return time.Time{}, 0, err
	}
	return st.ModTime(), st.Size(), nil
}

// absDomainName returns an absolute domain name which ends with a
// trailing dot to match pure Go reverse resolver and all other lookup
// routines.
// See golang.org/issue/12189.
// But we don't want to add dots for local names from /etc/hosts.
// It's hard to tell so we settle on the heuristic that names without dots
// (like "localhost" or "myhost") do not get trailing dots, but any other
// names do.
func absDomainName(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	hasDots := false
	for _, x := range b[:len(b)-1] {
		if x == '.' {
			hasDots = true
			break
		}
	}

	if hasDots && b[len(b)-1] != '.' {
		b = append(b, '.')
	}
	// strip trailing zero
	if !hasDots && b[len(b)-1] == '.' {
		b = b[:len(b)-1]
	}

	return string(b)
}

func readHosts() {
	now := time.Now()
	hp := hostsPath

	if now.Before(hosts.expire) && hosts.path == hp && len(hosts.byName) > 0 {
		return
	}
	mtime, size, err := stat(hp)
	if err == nil && hosts.path == hp && hosts.mtime.Equal(mtime) && hosts.size == size {
		hosts.expire = now.Add(cacheMaxAge)
		return
	}

	hs := make(map[string][]string)
	is := make(map[string][]string)
	var file *os.File
	if file, _ = os.Open(hp); file == nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			// Discard comments.
			line = line[0:i]
		}
		f := getFields(line)
		if len(f) < 2 {
			continue
		}
		addr := parseLiteralIP(f[0])
		if addr == "" {
			continue
		}
		for i := 1; i < len(f); i++ {
			name := absDomainName([]byte(f[i]))
			h := []byte(f[i])
			lowerASCIIBytes(h)
			key := absDomainName(h)
			hs[key] = append(hs[key], addr)
			is[addr] = append(is[addr], name)
		}
	}
	// ignore scanner error

	// Update the data cache.
	hosts.expire = now.Add(cacheMaxAge)
	hosts.path = hp
	hosts.byName = hs
	hosts.byAddr = is
	hosts.mtime = mtime
	hosts.size = size
}

// lowerASCIIBytes makes x ASCII lowercase in-place.
func lowerASCIIBytes(x []byte) {
	for i, b := range x {
		if 'A' <= b && b <= 'Z' {
			x[i] += 'a' - 'A'
		}
	}
}

// Split s at any bytes in t.
func splitAtBytes(s string, t string) []string {
	a := make([]string, 1+countAnyByte(s, t))
	n := 0
	last := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			if last < i {
				a[n] = s[last:i]
				n++
			}
			last = i + 1
		}
	}
	if last < len(s) {
		a[n] = s[last:]
		n++
	}
	return a[0:n]
}

// Count occurrences in s of any bytes in t.
func countAnyByte(s string, t string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(t, s[i]) >= 0 {
			n++
		}
	}
	return n
}

func getFields(s string) []string { return splitAtBytes(s, " \r\t\n") }

// lookupStaticHost looks up the addresses for the given host from /etc/hosts.
func lookupStaticHost(host string) []string {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	if len(hosts.byName) != 0 {
		// TODO(jbd,bradfitz): avoid this alloc if host is already all lowercase?
		// or linear scan the byName map if it's small enough?
		lowerHost := []byte(host)
		lowerASCIIBytes(lowerHost)
		if ips, ok := hosts.byName[absDomainName(lowerHost)]; ok {
			ipsCp := make([]string, len(ips))
			copy(ipsCp, ips)
			return ipsCp
		}
	}
	return nil
}

// lookupStaticAddr looks up the hosts for the given address from /etc/hosts.
func lookupStaticAddr(addr string) []string {
	hosts.Lock()
	defer hosts.Unlock()
	readHosts()
	addr = parseLiteralIP(addr)
	if addr == "" {
		return nil
	}
	if len(hosts.byAddr) != 0 {
		if hosts, ok := hosts.byAddr[addr]; ok {
			hostsCp := make([]string, len(hosts))
			copy(hostsCp, hosts)
			return hostsCp
		}
	}
	return nil
}
