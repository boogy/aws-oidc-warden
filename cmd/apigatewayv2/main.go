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
	defer bootstrap.Cleanup()
	h := handler.NewAwsApiGatewayV2FromBootstrap(bootstrap)
	lambda.Start(h.Handler)
}
