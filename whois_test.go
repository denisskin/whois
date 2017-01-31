package whois

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLoadRawDomainInfo(t *testing.T) {
	inf, err := LoadRawDomainInfo("golang.org")

	assert.NoError(t, err)
	assert.Contains(t, string(inf), "Domain Name: GOLANG.ORG")
	assert.Contains(t, string(inf), "Creation Date: 2009-08-21T20:27:16Z")
}
