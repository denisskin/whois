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

func TestLoadDomainInfo(t *testing.T) {
	inf, err := LoadDomainInfo("golang.org")

	assert.NoError(t, err)
	assert.True(t, len(inf.Params) > 0)
	assert.Equal(t, "2009-08-21T20:27:16Z", inf.GetParam("Creation Date"))
	assert.True(t, len(inf.NameServers()) > 0)
}
