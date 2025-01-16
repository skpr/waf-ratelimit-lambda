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

// Enables the specified LoggingConfiguration, to start logging from a web ACL, according to the
// configuration provided.
//
// This operation completely replaces any mutable specifications that you already
// have for a logging configuration with the ones that you provide to this call.
//
// To modify an existing logging configuration, do the following:
//
//   - Retrieve it by calling GetLoggingConfiguration
//
//   - Update its settings as needed
//
//   - Provide the complete logging configuration specification to this call
//
// You can define one logging destination per web ACL.
//
// You can access information about the traffic that WAF inspects using the
// following steps:
//
//   - Create your logging destination. You can use an Amazon CloudWatch Logs log
//     group, an Amazon Simple Storage Service (Amazon S3) bucket, or an Amazon Kinesis
//     Data Firehose.
//
// The name that you give the destination must start with aws-waf-logs- . Depending
//
//	on the type of destination, you might need to configure additional settings or
//	permissions.
//
// For configuration requirements and pricing information for each destination
//
//	type, see [Logging web ACL traffic]in the WAF Developer Guide.
//
//	- Associate your logging destination to your web ACL using a
//	PutLoggingConfiguration request.
//
// When you successfully enable logging using a PutLoggingConfiguration request,
// WAF creates an additional role or policy that is required to write logs to the
// logging destination. For an Amazon CloudWatch Logs log group, WAF creates a
// resource policy on the log group. For an Amazon S3 bucket, WAF creates a bucket
// policy. For an Amazon Kinesis Data Firehose, WAF creates a service-linked role.
//
// For additional information about web ACL logging, see [Logging web ACL traffic information] in the WAF Developer
// Guide.
//
// [Logging web ACL traffic information]: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
//
// [Logging web ACL traffic]: https://docs.aws.amazon.com/waf/latest/developerguide/logging.html
func (c *Client) PutLoggingConfiguration(ctx context.Context, params *PutLoggingConfigurationInput, optFns ...func(*Options)) (*PutLoggingConfigurationOutput, error) {
	if params == nil {
		params = &PutLoggingConfigurationInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "PutLoggingConfiguration", params, optFns, c.addOperationPutLoggingConfigurationMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*PutLoggingConfigurationOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type PutLoggingConfigurationInput struct {

	//
	//
	// This member is required.
	LoggingConfiguration *types.LoggingConfiguration

	noSmithyDocumentSerde
}

type PutLoggingConfigurationOutput struct {

	//
	LoggingConfiguration *types.LoggingConfiguration

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationPutLoggingConfigurationMiddlewares(stack *middleware.Stack, options Options) (err error) {
	if err := stack.Serialize.Add(&setOperationInputMiddleware{}, middleware.After); err != nil {
		return err
	}
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpPutLoggingConfiguration{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpPutLoggingConfiguration{}, middleware.After)
	if err != nil {
		return err
	}
	if err := addProtocolFinalizerMiddlewares(stack, options, "PutLoggingConfiguration"); err != nil {
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
	if err = addOpPutLoggingConfigurationValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opPutLoggingConfiguration(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opPutLoggingConfiguration(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		OperationName: "PutLoggingConfiguration",
	}
}
