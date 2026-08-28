package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// fallbackErrorBody is returned if marshaling the Response itself fails.
// A constant, never fmt.Sprintf with err.Error(), so an internal error
// string can't leak to the caller or break the JSON via unescaped chars.
const fallbackErrorBody = `{"success":false,"statusCode":500,"errorCode":"internal_error","message":"An internal error occurred"}`

// requestMeta extracts the request ID and elapsed time from ctx. No fallback
// on empty: minting a second UUID would report an ID absent from any log line.
func requestMeta(ctx context.Context) (requestID string, processingMS int64) {
	requestID, _ = ctx.Value(RequestIDContextKey).(string)
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}
	return requestID, processingMS
}

// buildErrorResponse classifies err into the shared Response shape via
// classifyError (which may override statusCode), logs it, and returns the
// response and final status. Shared by every adapter's respondError.
func buildErrorResponse(ctx context.Context, err error, statusCode int) (Response, int) {
	requestID, processingMS := requestMeta(ctx)
	errCode, errMsg := classifyError(err, &statusCode)

	slog.Error("Request error",
		slog.String("requestId", requestID),
		slog.String("errorCode", errCode),
		slog.String("error", err.Error()),
		slog.Int("status", statusCode),
		slog.Int64("processingMs", processingMS))

	// err.Error() is logged above but never in the response body: internal
	// detail must not reach unauthenticated callers.
	return Response{
		Success:      false,
		StatusCode:   statusCode,
		ErrorCode:    errCode,
		Message:      errMsg,
		RequestID:    requestID,
		ProcessingMS: processingMS,
	}, statusCode
}

// buildSuccessResponse builds the shared Response for a successful role
// assumption and logs it. Shared by every adapter's respondJSON.
func buildSuccessResponse(ctx context.Context, credentials *ststypes.Credentials) Response {
	requestID, processingMS := requestMeta(ctx)

	slog.Debug("Response successful",
		slog.String("requestId", requestID),
		slog.Int64("processingMs", processingMS))

	return Response{
		Success:      true,
		StatusCode:   http.StatusOK,
		Message:      "Token validation successful and role assumed",
		RequestID:    requestID,
		ProcessingMS: processingMS,
		Data:         credentials,
	}
}
