package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/denisskin/httpdoc"
)

// Import TLDs from www.iana.org to fresh whois.config
func main() {
	fmt.Println(`##`)
	fmt.Println(`# WHOIS servers for new TLDs (http://www.iana.org/domains/root/db)`)
	fmt.Println(`# Current as of`, time.Now().Format("2006-01-02"))
	fmt.Println(`# `)
	fmt.Println(`# https://github.com/denisskin/whois/`)
	fmt.Println(`##`)

	rootDoc := httpdoc.NewDocument("http://www.iana.org/domains/root/db")
	for _, lnk := range rootDoc.Links() {
		if url := lnk.Attributes["href"]; strings.HasPrefix(url, "/domains/root/db/") {
			doc := lnk.Doc()
			whoisServer := doc.Submatch(`(?is:<b>WHOIS Server:</b>\s*(\S+))`, 1)

			if whoisServer != "" {
				zone := strings.TrimPrefix(doc.URL().Path, "/domains/root/db/")
				zone = strings.TrimSuffix(zone, ".html")

				fmt.Printf("\n\\.%s$ %s", zone, whoisServer)
			}
		}
	}
}
