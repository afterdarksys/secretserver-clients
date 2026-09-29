// Package securemem owns guarded, locked plaintext buffers. It deliberately does
// not use MemGuard's encrypted Enclave API. No heap fallback is permitted.
// MemGuard attempts to disable core dumps; operators must also enforce core=0.
package securemem

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/awnumar/memguard"
)

var ErrDestroyed = errors.New("secure memory buffer has been destroyed")
var ErrUnavailable = errors.New("protected memory unavailable")

// ErrExhausted means one allocation did not fit the locked-page budget. It
// fails that request only; existing buffers and later allocations are fine.
// errors.Is(ErrExhausted, ErrUnavailable) is true.
var ErrExhausted = fmt.Errorf("%w: locked-memory budget exhausted", ErrUnavailable)

const MaxSecretSize = 1 << 20

// Locked-page budget. MemGuard panics on an mlock failure, and its panic path
// purges every allocation in the process. The adapter therefore counts the
// pages it locks and refuses an allocation before the kernel limit is hit.
// The budget is RLIMIT_MEMLOCK minus headroom for other code in the process
// that may lock memory (PKCS#11 modules, TLS libraries); with no finite limit
// it is defaultBudgetBytes.
const (
	headroomMinBytes   = 64 << 10
	headroomMaxBytes   = 1 << 20
	defaultBudgetBytes = 64 << 20
)

var pageSize = os.Getpagesize()
var budgetPages = -1 // computed on first allocation
var lockedPages int
var generation int // bumped by Purge; buffers from older generations hold no pages

// onPoison runs if MemGuard fails anyway (a panic inside the dependency). All
// buffers are gone at that point, so the process must restart.
var onPoison = func() {
	fmt.Fprintln(os.Stderr, "securemem: FATAL: protected memory failed (mlock/mprotect); MemGuard purged every buffer; exiting with status 70 for a supervised restart")
	os.Exit(70)
}

func budgetFromLimit(limit uint64, finite bool) int {
	if !finite {
		return defaultBudgetBytes / pageSize
	}
	headroom := limit / 8
	if headroom < headroomMinBytes {
		headroom = headroomMinBytes
	}
	if headroom > headroomMaxBytes {
		headroom = headroomMaxBytes
	}
	if limit <= headroom {
		return 0
	}
	return int((limit - headroom) / uint64(pageSize))
}

func pagesFor(size int) int { return (size + pageSize - 1) / pageSize }

// Healthy reports whether protected memory is usable. It is false only after
// a dependency failure, which also terminates the process (status 70).
func Healthy() bool {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	return !failed
}

// Usage returns locked pages in use and the budget, in pages.
func Usage() (used, budget int) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if budgetPages < 0 {
		budgetPages = budgetFromLimit(memlockLimit())
	}
	return lockedPages, budgetPages
}

// All memory operations and borrowed views share one lock because MemGuard may
// purge every allocation on failure. Never call MemGuard directly alongside
// this adapter, or reenter this package from a WithBytes callback.
var sessionMu sync.Mutex
var failed bool

// Buffer owns read-only locked plaintext until explicitly destroyed. It cannot
// erase copies made by callers or downstream cryptographic/network libraries.
type Buffer struct {
	memory *memguard.LockedBuffer
	size   int
	pages  int
	gen    int
}

func protected(fn func() error) (err error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	defer func() {
		if recover() != nil {
			failed = true
			err = ErrUnavailable
			onPoison()
		}
	}()
	return fn()
}

func allocate(size int, init func(*memguard.LockedBuffer)) (*Buffer, error) {
	if size < 1 || size > MaxSecretSize {
		return nil, fmt.Errorf("secret size must be 1–%d bytes", MaxSecretSize)
	}
	var b *Buffer
	err := protected(func() error {
		// After a dependency panic the process is exiting (onPoison); refuse
		// everything until then.
		if failed {
			return ErrUnavailable
		}
		if budgetPages < 0 {
			budgetPages = budgetFromLimit(memlockLimit())
		}
		need := pagesFor(size)
		if lockedPages+need > budgetPages {
			return ErrExhausted
		}
		p := memguard.NewBuffer(size)
		keep := false
		defer func() {
			if !keep {
				p.Destroy()
			}
		}()
		if p.Size() != size {
			return ErrUnavailable
		}
		if err := harden(p); err != nil {
			return err
		}
		if init != nil {
			init(p)
		}
		p.Freeze()
		b = &Buffer{memory: p, size: size, pages: need, gen: generation}
		lockedPages += need
		keep = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}
func New(size int) (*Buffer, error) { return allocate(size, nil) }

// Consume transfers ownership and wipes src on success and failure. Previous
// immutable strings and copies of src remain outside this ownership contract.
func Consume(src []byte) (*Buffer, error) {
	defer memguard.WipeBytes(src)
	return allocate(len(src), func(p *memguard.LockedBuffer) { p.Copy(src) })
}
func Random(size int) (*Buffer, error) {
	return allocate(size, func(p *memguard.LockedBuffer) { p.Scramble() })
}
func (b *Buffer) valid() error {
	if failed {
		return ErrUnavailable
	}
	if b.memory == nil || !b.memory.IsAlive() {
		return ErrDestroyed
	}
	return nil
}
func (b *Buffer) Len() int {
	sessionMu.Lock()
	defer sessionMu.Unlock()
	if b.valid() != nil {
		return 0
	}
	return b.size
}
func (b *Buffer) String() string   { return "[protected secret]" }
func (b *Buffer) GoString() string { return "[protected secret]" }
func (b *Buffer) MarshalJSON() ([]byte, error) {
	return nil, errors.New("protected secrets cannot be serialized")
}
func (b *Buffer) WriteAt(src []byte, offset int) (int, error) {
	err := protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		if offset < 0 || offset > b.size || len(src) > b.size-offset {
			return errors.New("secure memory write out of bounds")
		}
		b.memory.Melt()
		defer b.memory.Freeze()
		b.memory.CopyAt(offset, src)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(src), nil
}

// WithBytes borrows an immutable locked view. Do not retain, mutate, convert to
// string, or reenter this adapter from the callback. Keep callbacks short: all
// adapter operations are serialized. Callback panics return a redacted error.
func (b *Buffer) WithBytes(fn func([]byte) error) error {
	if fn == nil {
		return errors.New("secure memory callback is nil")
	}
	return protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		return invoke(fn, b.memory.Bytes())
	})
}
func invoke(fn func([]byte) error, p []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return fn(p)
}

// CopyTo copies directly between locked buffers without allocating a snapshot.
func (b *Buffer) CopyTo(dst *Buffer) error {
	if dst == nil || b == dst {
		return errors.New("invalid secure memory destination")
	}
	return protected(func() error {
		if err := b.valid(); err != nil {
			return err
		}
		if err := dst.valid(); err != nil {
			return err
		}
		if b.size != dst.size {
			return errors.New("secure memory size mismatch")
		}
		dst.memory.Melt()
		defer dst.memory.Freeze()
		dst.memory.Copy(b.memory.Bytes())
		return nil
	})
}

// Destroy wipes and frees owned memory. It is idempotent, including after purge.
func (b *Buffer) Destroy() error {
	return protected(func() error {
		if b.memory != nil {
			b.memory.Destroy()
			b.memory = nil
			if b.gen == generation {
				lockedPages -= b.pages
			}
		}
		b.pages = 0
		b.size = 0
		return nil
	})
}

// Purge invalidates all adapter buffers. Only executables should call this,
// after draining work at shutdown.
func Purge() error {
	return protected(func() error {
		memguard.Purge()
		lockedPages = 0
		generation++
		return nil
	})
}
