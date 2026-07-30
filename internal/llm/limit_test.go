package llm

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type concurrencyModel struct {
	active  atomic.Int32
	maximum atomic.Int32
}

func (m *concurrencyModel) Generate(context.Context, []*schema.Message, ...model.Option) (*schema.Message, error) {
	current := m.active.Add(1)
	defer m.active.Add(-1)
	for {
		previous := m.maximum.Load()
		if current <= previous || m.maximum.CompareAndSwap(previous, current) {
			break
		}
	}
	time.Sleep(10 * time.Millisecond)
	return &schema.Message{}, nil
}

func (m *concurrencyModel) Stream(context.Context, []*schema.Message, ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return schema.StreamReaderFromArray([]*schema.Message{{}}), nil
}

func (m *concurrencyModel) WithTools([]*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	return m, nil
}

func TestLimitConcurrencySharesLimitAcrossBoundModels(t *testing.T) {
	base := &concurrencyModel{}
	limited, err := LimitConcurrency(base, 2)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := limited.(model.ToolCallingChatModel).WithTools(nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = bound.Generate(context.Background(), nil)
		}()
	}
	for range 8 {
		<-done
	}
	if base.maximum.Load() > 2 {
		t.Fatalf("maximum concurrency = %d", base.maximum.Load())
	}
}
