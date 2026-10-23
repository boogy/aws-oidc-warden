package idp

import (
	"strings"

	"github.com/boogy/aws-oidc-warden/internal/utils"
)

const (
	subjLiteral = iota
	subjRoleARN
	subjAccountID
	subjRoleName
	subjSourceIssuer
	subjSourceSubject
)

var subjectPlaceholders = []struct {
	token string
	kind  int
}{
	{"{role_arn}", subjRoleARN},
	{"{account_id}", subjAccountID},
	{"{role_name}", subjRoleName},
	{"{source_issuer}", subjSourceIssuer},
	{"{source_subject}", subjSourceSubject},
}

type subjectPart struct {
	kind int
	lit  string
}

func compileSubjectTemplate(tmpl string) []subjectPart {
	var parts []subjectPart
	lit := 0
	for i := 0; i < len(tmpl); {
		kind, n := 0, 0
		if tmpl[i] == '{' {
			for _, p := range subjectPlaceholders {
				if strings.HasPrefix(tmpl[i:], p.token) {
					kind, n = p.kind, len(p.token)
					break
				}
			}
		}
		if kind == subjLiteral {
			i++
			continue
		}
		if i > lit {
			parts = append(parts, subjectPart{kind: subjLiteral, lit: tmpl[lit:i]})
		}
		parts = append(parts, subjectPart{kind: kind})
		i += n
		lit = i
	}
	if lit < len(tmpl) {
		parts = append(parts, subjectPart{kind: subjLiteral, lit: tmpl[lit:]})
	}
	return parts
}

func renderSubject(parts []subjectPart, roleARN, srcIss, srcSub string) (string, error) {
	account, name, err := utils.ParseRoleARN(roleARN)
	if err != nil || strings.Count(roleARN, ":") != 5 {
		return "", ErrInvalidSubject
	}
	vals := [...]string{subjRoleARN: roleARN, subjAccountID: account, subjRoleName: name, subjSourceIssuer: srcIss, subjSourceSubject: srcSub}
	size := 0
	for _, p := range parts {
		if p.kind == subjLiteral {
			size += len(p.lit)
		} else {
			size += len(vals[p.kind])
		}
	}
	if size > maxSubjectBytes {
		return "", ErrInvalidSubject
	}
	var b strings.Builder
	b.Grow(size)
	for _, p := range parts {
		if p.kind == subjLiteral {
			b.WriteString(p.lit)
		} else {
			b.WriteString(vals[p.kind])
		}
	}
	sub := b.String()
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
