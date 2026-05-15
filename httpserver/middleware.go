package httpserver

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// statusRecorder captures the status code written by an underlying handler so middleware
// can include it in access logs.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

// WriteHeader records the status code and forwards to the wrapped writer.
func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// logRequests wraps next with structured per-request access logs at info level.
//
// Logger is optional; nil logger turns logging off.
func logRequests(log *zap.Logger, next http.Handler) http.Handler {

	if log == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		log.Info("request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rec.status),
			zap.Duration("dur", time.Since(start)),
			zap.String("remote", r.RemoteAddr),
		)
	})
}
