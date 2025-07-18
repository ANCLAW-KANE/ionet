package main

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/likexian/whois"
)

var (
	whoisChan    = make(chan net.IP, 1000)
	whoisResults = make(map[string]string)
	whoisMux     sync.RWMutex

	duration = 5 * time.Second
	wh       = whois.DefaultClient.SetTimeout(duration)
)

func initWhois() {
	go func() {
		for ip := range whoisChan {
			ipStr := ip.String()
			whoisMux.RLock()
			_, exists := whoisResults[ipStr]
			whoisMux.RUnlock()

			if !exists {
				owner, isErr := getWhoisOwner(ipStr)
				if isErr {
					continue
				}
				whoisMux.Lock()
				whoisResults[ipStr] = owner
				whoisMux.Unlock()
			}
		}
	}()
}

func GetIPOwnerCached(ip net.IP) string {
	if ip.IsPrivate() || ip.IsLoopback() {
		return "local/private"
	}

	ipStr := ip.String()
	whoisMux.RLock()
	owner, exists := whoisResults[ipStr]
	whoisMux.RUnlock()

	if exists {
		return owner
	}

	select {
	case whoisChan <- ip:
	default:
	}

	return "resolving..."
}

func getWhoisOwner(ip string) (string, bool) {

	raw, err := wh.Whois(ip)
	if err != nil {
		return err.Error(), true
	}

	switch {
	case strings.Contains(raw, "ARIN"):
		return parseARIN(raw), false
	case strings.Contains(raw, "RIPE NCC"):
		return parseRIPE(raw), false
	case strings.Contains(raw, "APNIC"):
		return parseAPNIC(raw), false
	case strings.Contains(raw, "LACNIC"):
		return parseLACNIC(raw), false
	case strings.Contains(raw, "AFRINIC"):
		return parseAFRINIC(raw), false
	default:
		return parseGeneric(raw), false
	}
}
