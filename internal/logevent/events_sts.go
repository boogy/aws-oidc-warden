package logevent

// STSAssumeRoleStart is emitted before an AssumeRole call (Debug).
var STSAssumeRoleStart = newEvent("sts.assume_role.start")

// STSAssumeRoleSuccess is emitted when AssumeRole succeeds (Info).
var STSAssumeRoleSuccess = newEvent("sts.assume_role.success")

// STSAssumeRoleFailure is emitted when AssumeRole fails (Error).
var STSAssumeRoleFailure = newEvent("sts.assume_role.failure")

// STSSpokeAssumed is emitted when a spoke-account role is assumed (Info).
var STSSpokeAssumed = newEvent("sts.spoke.assumed")

// STSSessionNameTruncated is emitted when a session name is truncated to fit
// STS limits (Warn).
var STSSessionNameTruncated = newEvent("sts.session_name.truncated")

// STSDurationClamped is emitted when a requested session duration is
// clamped; attr clampReason explains why (Warn).
var STSDurationClamped = newEvent("sts.duration.clamped")

// STSSessionTagDropped is emitted when a session tag is dropped; attr
// dropReason: invalid_key, invalid_value, limit_reached (Warn).
var STSSessionTagDropped = newEvent("sts.session_tag.dropped")

// STSExternalIDSuspicious is emitted when a supplied external ID looks
// suspicious (Warn).
var STSExternalIDSuspicious = newEvent("sts.external_id.suspicious")

// STSCallerIdentityFailure is emitted when a GetCallerIdentity call fails
// (Error).
var STSCallerIdentityFailure = newEvent("sts.caller_identity.failure")
