// Package recovery classifies analysis failures and provides bounded,
// cancellation-aware retry timing.
package recovery

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"reflect"
	"time"
)

type Class string

const (
	ClassConfiguration     Class = "configuration"
	ClassAuthentication    Class = "authentication"
	ClassProviderTransient Class = "provider_transient"
	ClassProviderPermanent Class = "provider_permanent"
	ClassDeadline          Class = "deadline"
	ClassCanceled          Class = "canceled"
	ClassInventoryDrift    Class = "inventory_drift"
	ClassInvalidSubmission Class = "invalid_submission"
	ClassCheckpoint        Class = "checkpoint"
	ClassInternal          Class = "internal"
)

type Error struct {
	Class     Class
	Retryable bool
	Err       error
}

func (e *Error) Error() string {
	if e == nil || e.Err == nil {
		return string(e.Class)
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func Wrap(class Class, retryable bool, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Class: class, Retryable: retryable, Err: err}
}

type temporary interface{ Temporary() bool }
type httpStatusCode interface{ HTTPStatusCode() int }
type statusCode interface{ StatusCode() int }

func Classify(err error) (Class, bool) {
	if err == nil {
		return "", false
	}
	if classified, ok := errors.AsType[*Error](err); ok {
		return classified.Class, classified.Retryable
	}
	if errors.Is(err, context.Canceled) {
		return ClassCanceled, false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassDeadline, false
	}
	var status int
	if httpStatus, ok := errors.AsType[httpStatusCode](err); ok {
		status = httpStatus.HTTPStatusCode()
	} else if conventionalStatus, ok := errors.AsType[statusCode](err); ok {
		status = conventionalStatus.StatusCode()
	} else {
		status = reflectedStatusCode(err)
	}
	if status != 0 {
		switch status {
		case 401, 403:
			return ClassAuthentication, false
		case 408, 429, 500, 502, 503, 504:
			return ClassProviderTransient, true
		default:
			return ClassProviderPermanent, false
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ClassProviderTransient, true
	}
	var temp temporary
	if errors.As(err, &temp) && temp.Temporary() {
		return ClassProviderTransient, true
	}
	return ClassInternal, false
}

func Backoff(base time.Duration, failedAttempt int, random func() float64) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if failedAttempt < 1 {
		failedAttempt = 1
	}
	shift := min(failedAttempt-1, 20)
	const maximum = 15 * time.Minute
	multiplier := time.Duration(1 << shift)
	delay := maximum
	if base <= maximum/multiplier {
		delay = min(base*multiplier, maximum)
	}
	if random == nil {
		random = rand.Float64
	}
	// Full jitter in [50%, 100%) avoids synchronized retries while retaining a
	// useful lower bound for provider recovery.
	return time.Duration(float64(delay) * (0.5 + 0.5*random()))
}

func reflectedStatusCode(err error) int {
	for current := err; current != nil; current = errors.Unwrap(current) {
		value := reflect.ValueOf(current)
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				continue
			}
			value = value.Elem()
		}
		if value.Kind() != reflect.Struct {
			continue
		}
		field := value.FieldByName("StatusCode")
		if field.IsValid() && field.CanInt() {
			return int(field.Int())
		}
		response := value.FieldByName("Response")
		if response.IsValid() && response.Kind() == reflect.Pointer && !response.IsNil() {
			response = response.Elem()
			if response.Kind() == reflect.Struct {
				field = response.FieldByName("StatusCode")
				if field.IsValid() && field.CanInt() {
					return int(field.Int())
				}
			}
		}
	}
	return 0
}

func Wait(ctx context.Context, delay time.Duration, after func(time.Duration) <-chan time.Time) error {
	if delay < 0 {
		return fmt.Errorf("retry delay cannot be negative")
	}
	if after == nil {
		after = time.After
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-after(delay):
		return nil
	}
}
