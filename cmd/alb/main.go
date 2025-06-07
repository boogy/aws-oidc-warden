package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/pkg/handler"
)

func main() {
	// Initialize all components using bootstrap
	bootstrap, err := handler.NewBootstrap()
	if err != nil {
		panic(err)
	}

	// Ensure cleanup happens when the function exits
	defer bootstrap.Cleanup()

	// Create the ALB handler
	albHandler := handler.NewAwsApplicationLoadBalancerFromBootstrap(bootstrap)

	// Start the Lambda function
	lambda.Start(albHandler.Handler)
}
