// Code generated by smithy-go-codegen DO NOT EDIT.

package wafv2

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Retrieves the IP addresses that are currently blocked by a rate-based rule
// instance. This is only available for rate-based rules that aggregate solely on
// the IP address or on the forwarded IP address.
//
// The maximum number of addresses that can be blocked for a single rate-based
// rule instance is 10,000. If more than 10,000 addresses exceed the rate limit,
// those with the highest rates are blocked.
//
// For a rate-based rule that you've defined inside a rule group, provide the name
// of the rule group reference statement in your request, in addition to the
// rate-based rule name and the web ACL name.
//
// WAF monitors web requests and manages keys independently for each unique
// combination of web ACL, optional rule group, and rate-based rule. For example,
// if you define a rate-based rule inside a rule group, and then use the rule group
// in a web ACL, WAF monitors web requests and manages keys for that web ACL, rule
// group reference statement, and rate-based rule instance. If you use the same
// rule group in a second web ACL, WAF monitors web requests and manages keys for
// this second usage completely independent of your first.
func (c *Client) GetRateBasedStatementManagedKeys(ctx context.Context, params *GetRateBasedStatementManagedKeysInput, optFns ...func(*Options)) (*GetRateBasedStatementManagedKeysOutput, error) {
	if params == nil {
		params = &GetRateBasedStatementManagedKeysInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GetRateBasedStatementManagedKeys", params, optFns, c.addOperationGetRateBasedStatementManagedKeysMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GetRateBasedStatementManagedKeysOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetRateBasedStatementManagedKeysInput struct {

	// The name of the rate-based rule to get the keys for. If you have the rule
	// defined inside a rule group that you're using in your web ACL, also provide the
	// name of the rule group reference statement in the request parameter
	// RuleGroupRuleName .
	//
	// This member is required.
	RuleName *string

	// Specifies whether this is for an Amazon CloudFront distribution or for a
	// regional application. A regional application can be an Application Load Balancer
	// (ALB), an Amazon API Gateway REST API, an AppSync GraphQL API, an Amazon Cognito
	// user pool, an App Runner service, or an Amazon Web Services Verified Access
	// instance.
	//
	// To work with CloudFront, you must also specify the Region US East (N. Virginia)
	// as follows:
	//
	//   - CLI - Specify the Region when you use the CloudFront scope:
	//   --scope=CLOUDFRONT --region=us-east-1 .
	//
	//   - API and SDKs - For all calls, use the Region endpoint us-east-1.
	//
	// This member is required.
	Scope types.Scope

	// The unique identifier for the web ACL. This ID is returned in the responses to
	// create and list commands. You provide it to operations like update and delete.
	//
	// This member is required.
	WebACLId *string

	// The name of the web ACL. You cannot change the name of a web ACL after you
	// create it.
	//
	// This member is required.
	WebACLName *string

	// The name of the rule group reference statement in your web ACL. This is
	// required only when you have the rate-based rule nested inside a rule group.
	RuleGroupRuleName *string

	noSmithyDocumentSerde
}

type GetRateBasedStatementManagedKeysOutput struct {

	// The keys that are of Internet Protocol version 4 (IPv4).
	ManagedKeysIPV4 *types.RateBasedStatementManagedKeysIPSet

	// The keys that are of Internet Protocol version 6 (IPv6).
	ManagedKeysIPV6 *types.RateBasedStatementManagedKeysIPSet

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGetRateBasedStatementManagedKeysMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpGetRateBasedStatementManagedKeys{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetRateBasedStatementManagedKeys{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "GetRateBasedStatementManagedKeys"); err != nil {
		return fmt.Errorf("add protocol finalizers: %v", err)
	}

	if err = addlegacyEndpointContextSetter(stack, options); err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = addClientRequestID(stack); err != nil {
		return err
	}
	if err = addComputeContentLength(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = addComputePayloadSHA256(stack); err != nil {
		return err
	}
	if err = addRetry(stack, options); err != nil {
		return err
	}
	if err = addRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = addRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addSpanRetryLoop(stack, options); err != nil {
		return err
	}
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addSetLegacyContextSigningOptionsMiddleware(stack); err != nil {
		return err
	}
	if err = addTimeOffsetBuild(stack, c); err != nil {
		return err
	}
	if err = addUserAgentRetryMode(stack, options); err != nil {
		return err
	}
	if err = addOpGetRateBasedStatementManagedKeysValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGetRateBasedStatementManagedKeys(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	if err = addDisableHTTPSMiddleware(stack, options); err != nil {
		return err
	}
	if err = addSpanInitializeStart(stack); err != nil {
		return err
	}
	if err = addSpanInitializeEnd(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestStart(stack); err != nil {
		return err
	}
	if err = addSpanBuildRequestEnd(stack); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opGetRateBasedStatementManagedKeys(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "GetRateBasedStatementManagedKeys",
	}
}
