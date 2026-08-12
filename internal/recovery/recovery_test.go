package recovery

import (
	"context"
	"errors"
	"testing"
	"time"
)

type statusError int

func (e statusError) Error() string   { return "provider error" }
func (e statusError) StatusCode() int { return int(e) }

type unknownError struct{}

func (unknownError) Error() string { return "unknown" }

func TestClassifyUsesTypedFailuresAndDefaultsClosed(t *testing.T) {
	tests := []struct {
		err       error
		class     Class
		retryable bool
	}{
		{context.Canceled, ClassCanceled, false},
		{context.DeadlineExceeded, ClassDeadline, false},
		{statusError(429), ClassProviderTransient, true},
		{statusError(503), ClassProviderTransient, true},
		{statusError(401), ClassAuthentication, false},
		{statusError(400), ClassProviderPermanent, false},
		{unknownError{}, ClassInternal, false},
		{Wrap(ClassInventoryDrift, false, errors.New("drift")), ClassInventoryDrift, false},
	}
	for _, test := range tests {
		class, retryable := Classify(test.err)
		if class != test.class || retryable != test.retryable {
			t.Errorf("Classify(%v) = %s, %t; want %s, %t", test.err, class, retryable, test.class, test.retryable)
		}
	}
}

func TestBackoffAndWaitAreBoundedAndCancelable(t *testing.T) {
	if got := Backoff(time.Second, 3, func() float64 { return 0 }); got != 2*time.Second {
		t.Fatalf("backoff = %s, want 2s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Wait(ctx, time.Hour, func(time.Duration) <-chan time.Time { return make(chan time.Time) }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait returned %v", err)
	}
}
