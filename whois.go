package whois

import (
	"errors"
	"io/ioutil"
	"net"
	"regexp"
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

func LoadDomainInfo(domain string) (*WhoisInfo, error) {
	if data, err := LoadRawDomainInfo(domain); err != nil {
		return nil, err
	} else {
		return ParseWhoisInfo(domain, data), nil
	}
}

type WhoisInfo struct {
	Domain  string
	RawData []byte
	Params  map[string][]string
}

var reParam = regexp.MustCompile(`[\r\n]\s*([a-zA-Z0-9\- /\\_]+):\s*(.*)`)

func normalizeParamName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ToLower(name)
	name = strings.Replace(name, "-", " ", -1)
	return name
}

func ParseWhoisInfo(domain string, data []byte) *WhoisInfo {
	mm := reParam.FindAllStringSubmatch(string(data), -1)
	if len(mm) == 0 {
		return nil
	}
	inf := &WhoisInfo{
		Domain:  domain,
		RawData: data,
		Params:  map[string][]string{},
	}
	for _, m := range mm {
		name := normalizeParamName(m[1])
		inf.Params[name] = append(inf.Params[name], strings.TrimSpace(m[2]))
	}
	return inf
}

func (i *WhoisInfo) GetParam(name string) string {
	if ss := i.Params[normalizeParamName(name)]; len(ss) > 0 {
		return ss[0]
	}
	return ""
}

func (i *WhoisInfo) NameServers() (v []string) {
	v = append(v, i.Params["n server"]...)
	v = append(v, i.Params["name server"]...)
	return
}

func (i *WhoisInfo) WhoisServer() (v string) {
	if v = i.GetParam("whois"); v != "" {
		return
	}
	if v = i.GetParam("whois server"); v != "" {
		return
	}
	return
}
