package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/internal/handler"
)

var bootstrap *handler.Bootstrap

func init() {
	var err error
	bootstrap, err = handler.NewBootstrap()
	if err != nil {
		panic(err)
	}
}

func main() {
	// Create the API Gateway handler
	apiHandler := handler.NewAwsApiGatewayFromBootstrap(bootstrap)

	// Start the Lambda function
	lambda.StartWithOptions(apiHandler.Handler, lambda.WithEnableSIGTERM(bootstrap.Cleanup))
}
