package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/pkg/handler"
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
	// Ensure cleanup happens when the function exits
	defer bootstrap.Cleanup()

	// Create the Lambda URL handler
	lambdaHandler := handler.NewAwsLambdaUrlFromBootstrap(bootstrap)

	// Start the Lambda function
	lambda.Start(lambdaHandler.Handler)
}
