// Code generated by smithy-go-codegen DO NOT EDIT.

package wafv2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Generates a presigned download URL for the specified release of the mobile SDK.
// The mobile SDK is not generally available. Customers who have access to the
// mobile SDK can use it to establish and manage WAF tokens for use in HTTP(S)
// requests from a mobile device to WAF. For more information, see WAF client
// application integration
// (https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html)
// in the WAF Developer Guide.
func (c *Client) GenerateMobileSdkReleaseUrl(ctx context.Context, params *GenerateMobileSdkReleaseUrlInput, optFns ...func(*Options)) (*GenerateMobileSdkReleaseUrlOutput, error) {
	if params == nil {
		params = &GenerateMobileSdkReleaseUrlInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "GenerateMobileSdkReleaseUrl", params, optFns, c.addOperationGenerateMobileSdkReleaseUrlMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*GenerateMobileSdkReleaseUrlOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GenerateMobileSdkReleaseUrlInput struct {

	// The device platform.
	//
	// This member is required.
	Platform types.Platform

	// The release version. For the latest available version, specify LATEST.
	//
	// This member is required.
	ReleaseVersion *string

	noSmithyDocumentSerde
}

type GenerateMobileSdkReleaseUrlOutput struct {

	// The presigned download URL for the specified SDK release.
	Url *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationGenerateMobileSdkReleaseUrlMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsAwsjson11_serializeOpGenerateMobileSdkReleaseUrl{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsjson11_deserializeOpGenerateMobileSdkReleaseUrl{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpGenerateMobileSdkReleaseUrlValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opGenerateMobileSdkReleaseUrl(options.Region), middleware.Before); err != nil {
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
	return nil
}

func newServiceMetadataMiddleware_opGenerateMobileSdkReleaseUrl(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "wafv2",
		OperationName: "GenerateMobileSdkReleaseUrl",
	}
}
