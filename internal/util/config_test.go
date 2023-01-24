package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	config, err := LoadConfig("testdata")
	assert.NoError(t, err)
	assert.Equal(t, "skpr-test", config.ClusterName)
	assert.Equal(t, "web-acl-id", config.WebACLId)
	assert.Equal(t, "web-acl-name", config.WebACLName)
	assert.Equal(t, "rule-name", config.RuleName)
	assert.Equal(t, []string{"http://example.com/slack-hook1", "http://example.com/slack-hook2"}, config.SlackWebhookURL)
}

func TestValidate(t *testing.T) {
	var tests = []struct {
		name   string
		config Config
		fails  bool
	}{
		{
			name: "Missing Config",
			config: Config{
				ClusterName: "skpr-test",
			},
			fails: true,
		},
		{
			name: "Seriously, Missing Config",
			config: Config{
				ClusterName: "skpr-test",
				WebACLId:    "web-acl-id",
			},
			fails: true,
		},
		{
			name: "Still Missing Config",
			config: Config{
				ClusterName: "skpr-test",
				WebACLId:    "web-acl-id",
				WebACLName:  "web-acl-name",
			},
			fails: true,
		},
		{
			name: "You Think We Would Have Fixed The Missing Config By Now",
			config: Config{
				ClusterName: "skpr-test",
				WebACLId:    "web-acl-id",
				WebACLName:  "web-acl-name",
				RuleName:    "rule-name",
			},
			fails: true,
		},
		{
			name: "All the Config",
			config: Config{
				ClusterName:     "skpr-test",
				WebACLId:        "web-acl-id",
				WebACLName:      "web-acl-name",
				RuleName:        "rule-name",
				SlackWebhookURL: []string{"http://example.com/slack-webhook"},
			},
			fails: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ans := tt.config.Validate()
			if len(ans) > 0 != tt.fails {
				t.Errorf("got %s, want %v", ans, tt.fails)
			}
		})
	}
}
