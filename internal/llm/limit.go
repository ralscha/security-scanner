package llm

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type limitedChatModel struct {
	base      model.ToolCallingChatModel
	semaphore chan struct{}
}

func LimitConcurrency(chatModel model.BaseChatModel, maximum int) (model.BaseChatModel, error) {
	if maximum <= 0 {
		return chatModel, nil
	}
	toolModel, ok := chatModel.(model.ToolCallingChatModel)
	if !ok {
		return nil, fmt.Errorf("chat model does not support immutable tool calling")
	}
	return &limitedChatModel{base: toolModel, semaphore: make(chan struct{}, maximum)}, nil
}

func (m *limitedChatModel) Generate(ctx context.Context, input []*schema.Message, options ...model.Option) (*schema.Message, error) {
	if err := m.acquire(ctx); err != nil {
		return nil, err
	}
	defer m.release()
	return m.base.Generate(ctx, input, options...)
}

func (m *limitedChatModel) Stream(ctx context.Context, input []*schema.Message, options ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	if err := m.acquire(ctx); err != nil {
		return nil, err
	}
	source, err := m.base.Stream(ctx, input, options...)
	if err != nil {
		m.release()
		return nil, err
	}
	reader, writer := schema.Pipe[*schema.Message](1)
	go func() {
		defer m.release()
		defer source.Close()
		defer writer.Close()
		for {
			message, receiveErr := source.Recv()
			if errors.Is(receiveErr, io.EOF) {
				return
			}
			if writer.Send(message, receiveErr) || receiveErr != nil {
				return
			}
		}
	}()
	return reader, nil
}

func (m *limitedChatModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	bound, err := m.base.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &limitedChatModel{base: bound, semaphore: m.semaphore}, nil
}

func (m *limitedChatModel) acquire(ctx context.Context) error {
	select {
	case m.semaphore <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *limitedChatModel) release() { <-m.semaphore }

var _ model.ToolCallingChatModel = (*limitedChatModel)(nil)
