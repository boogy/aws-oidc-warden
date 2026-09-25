package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/internal/handler"
)

var bootstrap *handler.Bootstrap

func init() {
	var err error
	bootstrap, err = handler.NewBootstrap("lambdaurl")
	if err != nil {
		panic(err)
	}
}

func main() {
	// Create the Lambda URL handler
	lambdaHandler := handler.NewAwsLambdaUrlFromBootstrap(bootstrap)

	// Start the Lambda function
	lambda.StartWithOptions(lambdaHandler.Handler, lambda.WithEnableSIGTERM(bootstrap.Cleanup))
}
