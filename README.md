# Actual whois list
Actual whois.config for new TLDs. (Source: http://www.iana.org/domains/root/db) 

## Setup actual whois.config for new TLDs (Linux, MacOS)
``` shell
wget https://raw.githubusercontent.com/denisskin/whois/master/whois.conf
sudo cp whois.conf /etc/whois.conf
```

## Golang utils for WHOIS
``` shell
go get github.com/denisskin/whois
```
