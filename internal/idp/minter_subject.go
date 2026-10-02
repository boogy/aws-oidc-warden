package idp

import (
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

func renderSubject(tmpl, roleARN, srcIss, srcSub string) (string, error) {
	account, name, err := utils.ParseRoleARN(roleARN)
	if err != nil || strings.Count(roleARN, ":") != 5 {
		return "", ErrInvalidSubject
	}
	sub := strings.NewReplacer("{role_arn}", roleARN, "{account_id}", account, "{role_name}", name, "{source_issuer}", srcIss, "{source_subject}", srcSub).Replace(tmpl)
	if len(sub) > maxSubjectBytes {
		return "", ErrInvalidSubject
	}
	if !strings.HasSuffix(sub, roleARN) {
		return "", ErrInvalidSubject
	}
	for i := 0; i < len(sub); i++ {
		if sub[i] < 0x21 || sub[i] > 0x7e {
			return "", ErrInvalidSubject
		}
	}
	return sub, nil
}
