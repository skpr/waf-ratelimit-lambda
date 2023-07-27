package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/ipinfo/go/v2/ipinfo"

	"github.com/skpr/waf-ratelimit-lambda/internal/cloudwatch"
	"github.com/skpr/waf-ratelimit-lambda/internal/iputils"
	"github.com/skpr/waf-ratelimit-lambda/internal/slack"
	"github.com/skpr/waf-ratelimit-lambda/internal/util"
)

var (
	// GitVersion overridden at build time by:
	//   -ldflags="-X main.GitVersion=${VERSION}"
	GitVersion string
)

func main() {
	lambda.Start(HandleLambdaEvent)
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

	var detail cloudwatch.EventDetail

	if err := json.Unmarshal(e.Detail, &detail); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	if !cloudwatch.HasBecomeAlarm(detail) {
		log.Printf("Skipping. Event did not become alarm (previous state = %s, current state = %s)\n",
			detail.PreviousState.Value,
			detail.State.Value)
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

	var (
		inputs []slack.PostMessageInput
		errors []error
	)

	for _, address := range resp.ManagedKeysIPV4.Addresses {
		client := ipinfo.NewClient(nil, nil, config.IPInfoToken)

		ip, err := iputils.GetIPfromCIDR(address)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to get IP info: %w", err))
			continue
		}

		info, err := client.GetIPInfo(net.ParseIP(ip))
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to get IP info: %w", err))
			continue
		}

		inputs = append(inputs, slack.PostMessageInput{
			IP:      address,
			City:    info.City,
			Region:  info.Region,
			Country: info.Country,
			Org:     info.Org,
		})
	}

	for _, ip := range resp.ManagedKeysIPV6.Addresses {
		inputs = append(inputs, slack.PostMessageInput{
			IP:      ip,
			City:    "Unknown",
			Region:  "Unknown",
			Country: "Unknown",
			Org:     "Unknown",
		})
	}

	if len(inputs) > 0 {
		log.Println("Sending Slack messages")

		for _, input := range inputs {
			err = slack.PostMessage(config, input)
			if err != nil {
				errors = append(errors, fmt.Errorf("failed to send Slack message: %w", err))
				continue
			}
		}
	} else {
		log.Println("No IPs were found. Skipping Slack messages...")
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors were reported during function execution: %v", errors)
	}

	log.Println("Function complete")

	return nil
}
