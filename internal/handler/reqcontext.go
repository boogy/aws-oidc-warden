package handler

import (
	"context"
	"net"
	"strings"

	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/google/uuid"
)

// resolveRequestID returns the canonical request ID plus the frontend's own ID.
//
// The canonical ID is the Lambda invocation UUID: it exists in every frontend
// mode and is always a UUID, whereas the per-frontend IDs are not
// interchangeable — API Gateway v2 issues opaque tokens like
// "CPyipjveDoEEPIA=", REST v1 and Lambda URLs issue UUIDs, and ALB issues
// nothing at all. Searching logs across frontends needs one shape.
//
// frontendID is returned rather than discarded because it is the only join key
// back to API Gateway / ALB access logs; both are logged, under distinct names.
// Outside Lambda (cmd/local, unit tests) there is no invocation ID, so a fresh
// UUID is minted — never the frontend ID, which would reintroduce the mixed
// shapes this function exists to eliminate.
func resolveRequestID(ctx context.Context, frontendID string) (requestID, frontendRequestID string) {
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		return lc.AwsRequestID, frontendID
	}
	return uuid.New().String(), frontendID
}

// ipSource records where a logged IP came from, so a reader of the audit trail
// can tell an attested value from a client-supplied one.
const (
	ipSourceFrontend     = "frontend"        // platform-attested: the frontend's own observation
	ipSourceForwardedFor = "x-forwarded-for" // client-supplied: spoofable, see clientIP
)

// clientIP resolves the requesting client's IP and reports its provenance.
//
// directIP is the frontend's own source-IP field when it has one (API Gateway
// v1/v2, Lambda URLs). That value is observed by AWS, not sent by the caller,
// so it is always preferred and reported as ipSourceFrontend.
//
// ALB events carry no such field, so X-Forwarded-For is the only option. The
// RIGHTMOST hop is taken, not the leftmost: ALB *appends* the TCP peer it
// actually observed to whatever XFF the client already sent. For
// "1.2.3.4, 203.0.113.7" the client supplied "1.2.3.4" and the load balancer
// appended "203.0.113.7", so every entry left of the last one is
// attacker-controlled. Taking the leftmost hop would log precisely the value an
// attacker chose.
//
// Caveat for the operator: if a trusted proxy (CloudFront, a second ALB) sits
// in front, the rightmost hop is that proxy, not the end client. Rightmost is
// still the correct default — it is the only entry with an attester — but such
// a topology needs a trusted-hop count, which this function deliberately does
// not guess at. See docs/LOGGING.md's "Source IP trust model" section.
//
// XFF-derived values are reported as ipSourceForwardedFor. Authorization never
// consults this IP; it is audit metadata. But a holder of a valid token could
// otherwise forge their apparent origin in the trail undetectably, so the
// provenance travels with the value rather than being inferred by the reader.
//
// Every candidate is parsed with net.ParseIP and dropped if it is not an
// address. That is what keeps a non-IP value from ever being logged as one:
// alb.go used to log the ELB target-group ARN in this field.
func clientIP(directIP string, headers map[string]string) (ip, source string) {
	if parsed := net.ParseIP(strings.TrimSpace(directIP)); parsed != nil {
		return parsed.String(), ipSourceFrontend
	}
	for name, value := range headers {
		if !strings.EqualFold(name, "x-forwarded-for") {
			continue
		}
		// Walk right-to-left: the last valid address is the closest thing to
		// an attested one. Scanning past an unparseable trailing entry keeps a
		// malformed append from discarding the whole header.
		hops := strings.Split(value, ",")
		for i := len(hops) - 1; i >= 0; i-- {
			if parsed := net.ParseIP(strings.TrimSpace(hops[i])); parsed != nil {
				return parsed.String(), ipSourceForwardedFor
			}
		}
	}
	return "", ""
}
