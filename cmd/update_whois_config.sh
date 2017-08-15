#!/usr/bin/env bash

cd $(dirname $0)

go run ./loadtlds/main.go >../whois.conf