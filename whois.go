package whois

import (
	"errors"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func ProviderByDomain(domain string) string {
	ss := strings.SplitN(domain, ".", -1)
	zone := ss[len(ss)-1]
	return Providers[zone]
}

func LoadRawDomainInfo(domain string) ([]byte, error) {

	provider := ProviderByDomain(domain)
	if provider == "" {
		return nil, errors.New("Unknown provider for domain " + domain)
	}

	conn, err := net.Dial("tcp", provider+":43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// write request
	if err := conn.SetWriteDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte(domain + "\r\n")); err != nil {
		return nil, err
	}

	// read response
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}

	return ioutil.ReadAll(conn)
}
