package iputils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetIPfromCIDR(t *testing.T) {
	ip, err := GetIPfromCIDR("1.2.3.4/32")
	assert.NoError(t, err)
	assert.Equal(t, "1.2.3.4", ip)

	_, err = GetIPfromCIDR("1.2.3.4")
	assert.Error(t, err)

	_, err = GetIPfromCIDR("1.2.3.4/16")
	assert.Error(t, err)
}
