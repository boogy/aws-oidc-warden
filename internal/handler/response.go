package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/google/uuid"
)

// requestMeta extracts the request ID and elapsed processing time from ctx,
// as set by each adapter's createRequestContext. Every frontend falls back to
// a freshly generated UUID when the event carried no request ID (e.g. ALB,
// or a proxy that doesn't set one) so responses/logs always have one.
func requestMeta(ctx context.Context) (requestID string, processingMS int64) {
	requestID, _ = ctx.Value(RequestIDContextKey).(string)
	if requestID == "" {
		requestID = uuid.New().String()
	}
	if startTime, ok := ctx.Value(StartTimeContextKey).(time.Time); ok {
		processingMS = time.Since(startTime).Milliseconds()
	}
	return requestID, processingMS
}

// buildErrorResponse classifies err into the shared Response shape (sentinel
// error → error code/message/status via classifyError), logs it, and returns
// the response along with the final status code (classifyError may override
// the statusCode passed in). Shared by every adapter's respondError to avoid
// duplicating this block per frontend; each adapter still wraps the result in
// its own Lambda event response type.
func buildErrorResponse(ctx context.Context, err error, statusCode int) (Response, int) {
	requestID, processingMS := requestMeta(ctx)
	errCode, errMsg := classifyError(err, &statusCode)

	slog.Error("Request error",
		slog.String("requestId", requestID),
		slog.String("errorCode", errCode),
		slog.String("error", err.Error()),
		slog.Int("status", statusCode),
		slog.Int64("processingMs", processingMS))

	return Response{
		Success:      false,
		StatusCode:   statusCode,
		ErrorCode:    errCode,
		Message:      errMsg,
		ErrorDetails: err.Error(),
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
