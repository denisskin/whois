#!/usr/bin/env bash

cd $(dirname $0)

go run ./loadtlds/main.go && mv whois.conf ../whois.conf

printProvidersGolang() {
    echo 'package whois'
    echo ''
    echo '// Providers for all TLDs'
    echo 'var Providers = map[string]string{'

    cat ../whois.conf|grep '\\.' | tr "$" ' ' |awk '{print "    \"" substr($1, 3) "\":\t\t\"" $2 "\","}'

    echo '}'
}

printProvidersGolang > ../providers.go
go fmt ../providers.go >/dev/null
