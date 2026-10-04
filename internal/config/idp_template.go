package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const idpIssuerPlaceholder = "{issuer}"

var (
	idpPlaceholder         = regexp.MustCompile(`\{[^{}]*\}`)
	idpAllowedPlaceholders = map[string]bool{"{role_arn}": true, "{account_id}": true, "{role_name}": true, "{source_issuer}": true, "{source_subject}": true}
	idpTemplateLiteral     = regexp.MustCompile(`^[A-Za-z0-9:/._@+=,#-]*$`)
	idpSourceIdentityLit   = regexp.MustCompile(`^[\w=,.@:-]*$`)
	idpClaimPlaceholder    = regexp.MustCompile(`^\{claim:([^{}]*)\}$`)
)

// validateSourceIdentityTemplate checks placeholders, the literal charset, and issuer binding.
func validateSourceIdentityTemplate(t string, issuerCount int) error {
	for _, p := range idpPlaceholder.FindAllString(t, -1) {
		if p == "{request_id}" || p == "{subject}" || p == idpIssuerPlaceholder {
			continue
		}
		if m := idpClaimPlaceholder.FindStringSubmatch(p); m != nil {
			if m[1] == "" {
				return errors.New("idp.source_identity {claim:} needs a claim name")
			}
			continue
		}
		return fmt.Errorf("idp.source_identity has unknown placeholder %s", p)
	}
	if !idpSourceIdentityLit.MatchString(idpPlaceholder.ReplaceAllString(t, "")) {
		return errors.New("idp.source_identity literal text must match [\\w=,.@:-]")
	}
	if issuerCount > 1 && !strings.Contains(t, idpIssuerPlaceholder) {
		return errors.New("idp.source_identity must contain {issuer} when more than one issuer is configured")
	}
	return nil
}

// validateSubjectTemplate keeps the role ARN as the sub's unambiguous suffix.
func validateSubjectTemplate(t string) error {
	if !strings.HasSuffix(t, IdPDefaultSubjectTemplate) {
		return errors.New("idp.subject_template must end with {role_arn}")
	}
	if strings.Count(t, IdPDefaultSubjectTemplate) != 1 {
		return errors.New("idp.subject_template must contain {role_arn} exactly once")
	}
	for _, p := range idpPlaceholder.FindAllString(t, -1) {
		if !idpAllowedPlaceholders[p] {
			return fmt.Errorf("idp.subject_template: unknown placeholder %s", p)
		}
	}
	if !idpTemplateLiteral.MatchString(idpPlaceholder.ReplaceAllString(t, "")) {
		return errors.New("idp.subject_template: literal text must match [A-Za-z0-9:/._@+=,#-]")
	}
	if subj := strings.Index(t, "{source_subject}"); subj >= 0 {
		iss := strings.Index(t, "{source_issuer}")
		if iss < 0 || iss > subj {
			return errors.New("idp.subject_template: {source_subject} requires {source_issuer} before it")
		}
		if !strings.Contains(t[iss+len("{source_issuer}"):subj], "#") {
			return errors.New("idp.subject_template: {source_issuer} and {source_subject} must be separated by #")
		}
	}
	return nil
}
