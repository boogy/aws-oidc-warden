package logevent

// AWSS3GetSuccess is emitted when an S3 GetObject call succeeds (Debug).
var AWSS3GetSuccess = newEvent("aws.s3.get.success")

// AWSS3GetFailure is emitted when an S3 GetObject call fails (Error).
var AWSS3GetFailure = newEvent("aws.s3.get.failure")

// AWSS3ObjectOversize is emitted when an S3 object exceeds the read bound
// (Warn).
var AWSS3ObjectOversize = newEvent("aws.s3.object.oversize")

// AWSIAMGetRoleSuccess is emitted when an IAM GetRole call succeeds (Debug).
var AWSIAMGetRoleSuccess = newEvent("aws.iam.get_role.success")

// AWSIAMGetRoleFailure is emitted when an IAM GetRole call fails (Error).
var AWSIAMGetRoleFailure = newEvent("aws.iam.get_role.failure")
