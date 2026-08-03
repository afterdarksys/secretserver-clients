package securemem

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
)

var ErrDestroyed = errors.New("secure memory buffer has been destroyed")

type Buffer struct {
	mu        sync.RWMutex
	data      []byte
	destroyed bool
}

func New(size int) (*Buffer, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secure memory size must be positive")
	}
	data, err := allocLocked(size)
	if err != nil {
		return nil, fmt.Errorf("allocate locked memory: %w", err)
	}
	b := &Buffer{data: data}
	runtime.SetFinalizer(b, func(leaked *Buffer) { _ = leaked.Destroy() })
	return b, nil
}

func Consume(src []byte) (*Buffer, error) {
	b, err := New(len(src))
	if err == nil {
		copy(b.data, src)
	}
	wipe(src)
	runtime.KeepAlive(src)
	return b, err
}

func (b *Buffer) WithBytes(fn func([]byte) error) error {
	if fn == nil {
		return fmt.Errorf("secure memory callback is nil")
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.destroyed {
		return ErrDestroyed
	}
	err := fn(b.data)
	runtime.KeepAlive(b)
	return err
}

func (b *Buffer) Destroy() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.destroyed {
		return nil
	}
	runtime.SetFinalizer(b, nil)
	wipe(b.data)
	runtime.KeepAlive(b.data)
	err := releaseLocked(b.data)
	b.data = nil
	b.destroyed = true
	return err
}

func wipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
