package util

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config used by this application.
type Config struct {
	ClusterName     string   `mapstructure:"SKPR_CLUSTER_NAME"`
	WebACLId        string   `mapstructure:"WAF_ACL_ID"`
	WebACLName      string   `mapstructure:"WAF_ACL_NAME"`
	RuleName        string   `mapstructure:"WAF_ACL_RULE_NAME"`
	IPInfoToken     string   `mapstructure:"IPINFO_TOKEN"`
	SlackWebhookURL []string `mapstructure:"SLACK_WEBHOOK_URL"`
}

// Validate checks that all required configuration is present.
func (c Config) Validate() []string {
	var errors []string

	if c.ClusterName == "" {
		errors = append(errors, "SKPR_CLUSTER_NAME is a required variable")
	}

	if c.WebACLId == "" {
		errors = append(errors, "WAF_ACL_ID is a required variable")
	}

	if c.WebACLName == "" {
		errors = append(errors, "WAF_ACL_NAME is a required variable")
	}

	if c.RuleName == "" {
		errors = append(errors, "WAF_ACL_RULE_NAME is a required variable")
	}

	if len(c.IPInfoToken) == 0 {
		errors = append(errors, "IPINFO_TOKEN is a required variable")
	}

	if len(c.SlackWebhookURL) == 0 {
		errors = append(errors, "SLACK_WEBHOOK_URL is a required variable")
	}

	return errors
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (Config, error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("defaults")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	var config Config

	err := viper.ReadInConfig()
	if err != nil {
		return config, fmt.Errorf("failed to read config: %w", err)
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return config, err
}
