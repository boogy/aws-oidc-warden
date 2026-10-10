package aws

import (
	"errors"
	"fmt"
	"strings"

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
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
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

// ErrAccountNotAllowed marks a target account refused by cross_account.
var ErrAccountNotAllowed = errors.New("target account is not allowed by cross_account")

var (
	ErrWebIdentityDenied                 = errors.New("sts:AssumeRoleWithWebIdentity denied by AWS")
	ErrWebIdentityUnavailable            = errors.New("sts:AssumeRoleWithWebIdentity could not reach the IdP")
	ErrWebIdentityDurationExceedsRoleMax = errors.New("sts:AssumeRoleWithWebIdentity duration exceeds role MaxSessionDuration")
	ErrWebIdentityPackedPolicyTooLarge   = errors.New("sts:AssumeRoleWithWebIdentity packed policy too large")
)

const (
	idpFetchRetrieveHint = "retrieve"
	idpFetchFetchHint    = "fetch"
	idpFetchKeyHint      = "verification key"
	roleMaxDurationHint  = "MaxSessionDuration"
	durationSecondsHint  = "DurationSeconds"
)

// classifyWebIdentityError wraps known STS failures in a marker error; others pass through unchanged.
func classifyWebIdentityError(err error) error {
	msg := err.Error()
	lower := strings.ToLower(msg)
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
		if strings.Contains(msg, durationSecondsHint) && strings.Contains(msg, roleMaxDurationHint) {
			return fmt.Errorf("%w: %w", ErrWebIdentityDurationExceedsRoleMax, err)
		}
	case "packedpolicytoolarge":
		return fmt.Errorf("%w: %w", ErrWebIdentityPackedPolicyTooLarge, err)
	}
	return err
}
