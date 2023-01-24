package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/skpr/waf-ratelimit-lambda/internal/util"
)

// PostMessage to Slack channel.
func PostMessage(config util.Config, body string) error {
	message := Message{
		Blocks: []Block{
			{
				Type: BlockTypeSection,
				Text: &BlockText{
					Type: BlockTextTypeMarkdown,
					Text: ":fire::fire: Rate Limit Rule Triggered :fire::fire:",
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
			{
				Type: BlockTypeSection,
				Text: &BlockText{
					Type: BlockTextTypeMarkdown,
					Text: body,
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
