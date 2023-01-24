package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/skpr/waf-ratelimit-lambda/internal/cloudwatch"
	"github.com/skpr/waf-ratelimit-lambda/internal/slack"
	"github.com/skpr/waf-ratelimit-lambda/internal/util"
)

var (
	// GitVersion overridden at build time by:
	//   -ldflags="-X main.GitVersion=${VERSION}"
	GitVersion string
)

func main() {
	if err := HandleLambdaEvent(context.TODO(), events.CloudWatchEvent{}); err != nil {
		panic(err)
	}
}

// HandleLambdaEvent will respond to a CloudWatch Alarm, check for rate limited IP addresses and send a message to Slack.
func HandleLambdaEvent(ctx context.Context, e events.CloudWatchEvent) error {
	log.Printf("Running Lambda (%s)\n", GitVersion)

	config, err := util.LoadConfig(".")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	errs := config.Validate()
	if len(errs) > 0 {
		return fmt.Errorf("configuration error: %s", strings.Join(errs, "\n"))
	}

	log.Println("Inspecting event")

	var event cloudwatch.Event

	if err := json.Unmarshal(e.Detail, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	if !cloudwatch.HasBecomeAlarm(event) {
		log.Printf("Skipping. Event did not become alarm (previous state = %s, current state = %s)\n",
			event.Detail.PreviousState.Value,
			event.Detail.State.Value)
		return nil
	}

	log.Println("Looking up IP addresses")

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := wafv2.NewFromConfig(cfg)

	resp, err := client.GetRateBasedStatementManagedKeys(ctx, &wafv2.GetRateBasedStatementManagedKeysInput{
		WebACLId:   aws.String(config.WebACLId),
		WebACLName: aws.String(config.WebACLName),
		RuleName:   aws.String(config.RuleName),
		Scope:      types.ScopeCloudfront,
	})
	if err != nil {
		return fmt.Errorf("failed to get IP addresses: %w", err)
	}

	var ips []string

	ips = append(ips, resp.ManagedKeysIPV4.Addresses...)
	ips = append(ips, resp.ManagedKeysIPV6.Addresses...)

	log.Println("Sending Slack messages")

	err = slack.PostMessage(config, getMessage(ips))
	if err != nil {
		return fmt.Errorf("failed to post Slack message: %w", err)
	}

	log.Println("Function complete")

	return nil
}

// Helper function to get message depends on if there are IP addresses.
func getMessage(ips []string) string {
	if len(ips) == 0 {
		return "IP addresses not found. Check sampling data for WAF and Rule."
	}

	return fmt.Sprintf("IP addresses currently rate limited:\n\n %s", strings.Join(ips, "\n"))
}
