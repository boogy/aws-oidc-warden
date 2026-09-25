package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/boogy/aws-oidc-warden/internal/handler"
)

var bootstrap *handler.Bootstrap

func init() {
	var err error
	bootstrap, err = handler.NewBootstrap("alb")
	if err != nil {
		panic(err)
	}
}

func main() {
	// Create the ALB handler
	albHandler := handler.NewAwsApplicationLoadBalancerFromBootstrap(bootstrap)

	// Start the Lambda function
	lambda.StartWithOptions(albHandler.Handler, lambda.WithEnableSIGTERM(bootstrap.Cleanup))
}
