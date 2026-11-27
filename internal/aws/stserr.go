package aws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/smithy-go"
)

// ErrAssumeRoleDenied marks an sts:AssumeRole failure AWS refused on authorization grounds.
var ErrAssumeRoleDenied = errors.New("sts:AssumeRole denied by AWS authorization")

// deniedCodes are lower-cased STS codes meaning authorization refused.
var deniedCodes = map[string]struct{}{
	"accessdenied":          {},
	"accessdeniedexception": {},
}

// STSErrorCode returns the AWS API error code, or "" for non-API errors.
func STSErrorCode(err error) string {
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		return apiErr.ErrorCode()
	}
	return ""
}

// classifyAssumeRoleError wraps an authorization refusal in ErrAssumeRoleDenied; other failures pass through.
func classifyAssumeRoleError(err error) error {
	if _, denied := deniedCodes[strings.ToLower(STSErrorCode(err))]; denied {
		return fmt.Errorf("%w: %w", ErrAssumeRoleDenied, err)
	}
	return err
}

// IsTransient reports whether err is a throttling, server-fault, connection or timeout failure a retry may clear.
func IsTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if (retry.RetryableHTTPStatusCode{Codes: retry.DefaultRetryableHTTPStatusCodes}).IsErrorRetryable(err) == aws.TrueTernary ||
		retry.IsErrorThrottles(retry.DefaultThrottles).IsErrorThrottle(err) == aws.TrueTernary {
		return true
	}
	if apiErr, ok := errors.AsType[smithy.APIError](err); ok {
		// The error text can carry the caller's role name, so an API error is never string-matched.
		return apiErr.ErrorFault() == smithy.FaultServer ||
			(retry.RetryableErrorCode{Codes: retry.DefaultRetryableErrorCodes}).IsErrorRetryable(err) == aws.TrueTernary
	}
	if dnsErr, ok := errors.AsType[*net.DNSError](err); errors.Is(err, context.Canceled) || ok && dnsErr.IsNotFound {
		return false
	}
	// Typed checks only: a local error's text can carry the caller's role name.
	var conErr interface{ ConnectionError() bool }
	var netErr net.Error
	var opErr *net.OpError
	return (errors.As(err, &conErr) && conErr.ConnectionError()) ||
		(errors.As(err, &netErr) && netErr.Timeout()) ||
		errors.As(err, &opErr) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// ErrAccountNotAllowed marks a target account refused by cross_account.
var ErrAccountNotAllowed = errors.New("target account is not allowed by cross_account")

var (
	// ErrWebIdentityDenied marks an AssumeRoleWithWebIdentity refusal that a retry will not fix.
	ErrWebIdentityDenied = errors.New("sts:AssumeRoleWithWebIdentity denied by AWS")
	// ErrWebIdentityUnavailable marks a retryable AssumeRoleWithWebIdentity failure.
	ErrWebIdentityUnavailable = errors.New("sts:AssumeRoleWithWebIdentity could not reach the IdP or the minted token expired")
	// ErrWebIdentityDurationExceedsRoleMax marks a DurationSeconds above the target role's MaxSessionDuration.
	ErrWebIdentityDurationExceedsRoleMax = errors.New("sts:AssumeRoleWithWebIdentity duration exceeds role MaxSessionDuration")
	// ErrWebIdentityPackedPolicyTooLarge marks a session policy plus tags over the STS packed size limit.
	ErrWebIdentityPackedPolicyTooLarge = errors.New("sts:AssumeRoleWithWebIdentity packed policy too large")
	// ErrWebIdentityIncompleteCredentials marks a successful AssumeRoleWithWebIdentity response with missing or partial credentials.
	ErrWebIdentityIncompleteCredentials = errors.New("sts:AssumeRoleWithWebIdentity returned missing or incomplete credentials")
)

const (
	idpFetchRetrieveHint = "retrieve"
	idpFetchFetchHint    = "fetch"
	idpFetchKeyHint      = "verification key"
	roleMaxDurationHint  = "durationseconds exceeds the maxsessionduration"
)

// classifyWebIdentityError wraps known STS failures in a marker error; others pass through unchanged.
func classifyWebIdentityError(err error) error {
	lower := strings.ToLower(err.Error())
	code := strings.ToLower(STSErrorCode(err))
	if _, denied := deniedCodes[code]; denied {
		return fmt.Errorf("%w: %w", ErrWebIdentityDenied, err)
	}
	switch code {
	case "idpcommunicationerror", "expiredtokenexception":
		return fmt.Errorf("%w: %w", ErrWebIdentityUnavailable, err)
	case "invalididentitytoken":
		if strings.Contains(lower, idpFetchRetrieveHint) || strings.Contains(lower, idpFetchFetchHint) || strings.Contains(lower, idpFetchKeyHint) {
			return fmt.Errorf("%w: %w", ErrWebIdentityUnavailable, err)
		}
		return fmt.Errorf("%w: %w", ErrWebIdentityDenied, err)
	case "idprejectedclaim":
		return fmt.Errorf("%w: %w", ErrWebIdentityDenied, err)
	case "validationerror":
		if strings.Contains(lower, roleMaxDurationHint) {
			return fmt.Errorf("%w: %w", ErrWebIdentityDurationExceedsRoleMax, err)
		}
	case "packedpolicytoolarge":
		return fmt.Errorf("%w: %w", ErrWebIdentityPackedPolicyTooLarge, err)
	}
	return err
}
