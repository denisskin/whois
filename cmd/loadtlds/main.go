package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/denisskin/httpdoc"
)

// Import TLDs from www.iana.org to fresh whois.config
func main() {

	f := bytes.NewBuffer(nil)

	f.WriteString("##\n")
	f.WriteString("# WHOIS servers for new TLDs (http://www.iana.org/domains/root/db)")
	f.WriteString("# Current as of " + time.Now().Format("2006-01-02") + "\n")
	f.WriteString("# \n")
	f.WriteString("# https://github.com/denisskin/whois/\n")
	f.WriteString("##\n")

	rootDoc := httpdoc.NewDocument("http://www.iana.org/domains/root/db")
	for _, lnk := range rootDoc.Links() {
		if url := lnk.Attributes["href"]; strings.HasPrefix(url, "/domains/root/db/") {
			doc := lnk.Doc()
			whoisServer := doc.Submatch(`(?is:<b>WHOIS Server:</b>\s*(\S+))`, 1)

			if whoisServer != "" {
				zone := strings.TrimPrefix(doc.URL().Path, "/domains/root/db/")
				zone = strings.TrimSuffix(zone, ".html")

				fmt.Fprintf(f, "\n\\.%s$ %s", zone, whoisServer)
				log.Printf("- %s\t%s", zone, whoisServer)
			}
		}
	}

	// save config to whois.config
	if err := ioutil.WriteFile("whois.conf", f.Bytes(), 0666); err != nil {
		log.Fatal(err)
	}
	log.Println("- whois.conf updated")
}
