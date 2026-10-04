//go:build linux || darwin

package securemem

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func runChild(t *testing.T, name, env string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+name+"$", "-test.v")
	cmd.Env = append(os.Environ(), env+"=1")
	return cmd.CombinedOutput()
}

// Exhausting the locked-memory limit must fail only the allocation that does
// not fit. Buffers already held stay usable and freeing one makes room again.
// (Previously the first mlock failure purged every buffer and poisoned the
// adapter until restart.)
func TestExhaustionFailsOnlyThatAllocation(t *testing.T) {
	if os.Getenv("SS_MEMORY_BUDGET_CHILD") == "1" {
		page := uint64(os.Getpagesize())
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 64 * page, Max: 64 * page}); err != nil {
			t.Fatal(err)
		}
		var held []*Buffer
		var failure error
		for i := 0; i < 200; i++ {
			b, err := Consume([]byte("held-secret"))
			if err != nil {
				failure = err
				break
			}
			held = append(held, b)
		}
		if failure == nil || len(held) == 0 {
			t.Fatalf("limit never reached (held %d)", len(held))
		}
		if !errors.Is(failure, ErrUnavailable) {
			t.Fatalf("exhaustion error: %v", failure)
		}
		for i := 0; i < 50; i++ {
			if b, err := Consume([]byte("retry")); b != nil || err == nil {
				t.Fatal("allocation beyond the limit succeeded")
			}
		}
		for _, b := range held {
			if err := b.WithBytes(func(p []byte) error {
				if string(p) != "held-secret" {
					t.Fatal("held buffer changed")
				}
				return nil
			}); err != nil {
				t.Fatalf("held buffer lost after exhaustion: %v", err)
			}
		}
		if err := held[0].Destroy(); err != nil {
			t.Fatal(err)
		}
		again, err := Consume([]byte("after-free"))
		if err != nil {
			t.Fatalf("allocation after freeing a buffer: %v", err)
		}
		again.Destroy()
		for _, b := range held[1:] {
			b.Destroy()
		}
		return
	}
	if out, err := runChild(t, "TestExhaustionFailsOnlyThatAllocation", "SS_MEMORY_BUDGET_CHILD"); err != nil {
		t.Fatalf("budget child: %v\n%s", err, out)
	}
}
