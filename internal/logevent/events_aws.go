package logevent

// AWSClientsRefreshSuccess is emitted when AWS SDK clients are refreshed
// (Info).
var AWSClientsRefreshSuccess = newEvent("aws.clients.refresh.success")

// AWSClientsRefreshFailure is emitted when refreshing AWS SDK clients fails
// (Error).
var AWSClientsRefreshFailure = newEvent("aws.clients.refresh.failure")

// AWSS3GetFailure is emitted when an S3 GetObject call fails (Error).
var AWSS3GetFailure = newEvent("aws.s3.get.failure")

// AWSS3ObjectOversize is emitted when an S3 object exceeds the read bound
// (Warn).
var AWSS3ObjectOversize = newEvent("aws.s3.object.oversize")

// AWSIAMGetRoleSuccess is emitted when an IAM GetRole call succeeds (Debug).
var AWSIAMGetRoleSuccess = newEvent("aws.iam.get_role.success")

// AWSIAMGetRoleFailure is emitted when an IAM GetRole call fails (Error).
var AWSIAMGetRoleFailure = newEvent("aws.iam.get_role.failure")

// AWSConfigImported is emitted when the AWS SDK config is loaded, carrying
// counts only (Debug).
var AWSConfigImported = newEvent("aws.config.imported")
