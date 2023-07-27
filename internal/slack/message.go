package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/skpr/waf-ratelimit-lambda/internal/util"
)

type PostMessageInput struct {
	IP      string
	City    string
	Region  string
	Country string
	Org     string
}

func (i PostMessageInput) Validate() error {
	var errors []error

	if i.IP == "" {
		errors = append(errors, fmt.Errorf("IP is a required field"))
	}

	if i.City == "" {
		errors = append(errors, fmt.Errorf("city is a required field"))
	}

	if i.Region == "" {
		errors = append(errors, fmt.Errorf("region is a required field"))
	}

	if i.Country == "" {
		errors = append(errors, fmt.Errorf("country is a required field"))
	}

	if i.Org == "" {
		errors = append(errors, fmt.Errorf("org is a required field"))
	}

	if len(errors) > 0 {
		return fmt.Errorf("invalid input: %v", errors)
	}

	return nil
}

// PostMessage to Slack channel.
func PostMessage(config util.Config, input PostMessageInput) error {
	message := Message{
		Blocks: []Block{
			{
				Type: BlockTypeHeader,
				Text: &BlockText{
					Type: BlockTextTypePlainText,
					Text: ":waf: Rate Limiting Rule Triggered for IP",
				},
			},
			{
				Type: BlockTypeContext,
				Elements: []BlockElement{
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*IP* = %s", input.IP)),
					},
				},
			},
			{
				Type: BlockTypeContext,
				Elements: []BlockElement{
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*City* = %s", input.City)),
					},
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*Region* = %s", input.Region)),
					},
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*Country* = %s", input.Country)),
					},
				},
			},
			{
				Type: BlockTypeContext,
				Elements: []BlockElement{
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*Org* = %s", input.Org)),
					},
				},
			},
			{
				Type: BlockTypeContext,
				Elements: []BlockElement{
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*Cluster* = %s", config.ClusterName)),
					},
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*WAF* = %s", config.WebACLName)),
					},
					{
						Type: BlockElementTypeMarkdown,
						Text: aws.String(fmt.Sprintf("*Rule* = %s", config.RuleName)),
					},
				},
			},
		},
	}

	request, err := json.Marshal(message)
	if err != nil {
		return err
	}

	for _, webhook := range config.SlackWebhookURL {
		req, err := http.NewRequest(http.MethodPost, webhook, bytes.NewBuffer(request))
		if err != nil {
			return err
		}

		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{}

		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		buf := new(bytes.Buffer)

		_, err = buf.ReadFrom(resp.Body)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("returned status code: %d", resp.StatusCode)
		}
	}

	return nil
}
