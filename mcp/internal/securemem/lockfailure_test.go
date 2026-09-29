//go:build linux || darwin

package securemem

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Lower process limits only in a disposable subprocess, never the test runner.
func TestLockFailureIsClosed(t *testing.T) {
	if os.Getenv("SS_MEMORY_LOCK_FAILURE_CHILD") == "1" {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
			t.Fatal(err)
		}
		src := []byte("disposable-test-secret")
		b, err := Consume(src)
		if b != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatalf("protection unexpectedly succeeded: %v", err)
		}
		if !bytes.Equal(src, make([]byte, len(src))) {
			t.Fatal("source not wiped on lock failure")
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockFailureIsClosed$", "-test.v")
	cmd.Env = append(os.Environ(), "SS_MEMORY_LOCK_FAILURE_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lock failure subprocess: %v\n%s", err, output)
	}
}

// If MemGuard fails anyway (here: the adapter budget is forced far above the
// kernel limit), every buffer is gone, so the process must exit with status 70
// for a supervised restart instead of serving on a poisoned adapter.
func TestDependencyFailureExitsForRestart(t *testing.T) {
	if os.Getenv("SS_MEMORY_POISON_CHILD") == "1" {
		page := uint64(os.Getpagesize())
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: page, Max: page}); err != nil {
			t.Fatal(err)
		}
		budgetPages = 1 << 20
		for i := 0; i < 8; i++ {
			if _, err := Consume([]byte("x")); err != nil {
				t.Fatalf("returned instead of exiting: %v", err)
			}
		}
		t.Fatal("kernel limit never reached")
	}
	out, err := runChild(t, "TestDependencyFailureExitsForRestart", "SS_MEMORY_POISON_CHILD")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 70 {
		t.Fatalf("want exit status 70, got %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("exiting with status 70")) {
		t.Fatalf("poison not logged:\n%s", out)
	}
}

func TestBudgetFromLimit(t *testing.T) {
	page := os.Getpagesize()
	if got := budgetFromLimit(8<<20, true); got != (8<<20-1<<20)/page {
		t.Fatalf("8 MiB limit: %d pages", got)
	}
	if got := budgetFromLimit(0, true); got != 0 {
		t.Fatalf("zero limit: %d", got)
	}
	if got := budgetFromLimit(0, false); got != (16<<20)/page {
		t.Fatalf("unlimited: %d", got)
	}
	if got := budgetFromLimit(256<<10, true); got != (256<<10-64<<10)/page {
		t.Fatalf("256 KiB limit: %d", got)
	}
}

func TestHealthyAndUsage(t *testing.T) {
	if !Healthy() {
		t.Fatal("adapter unhealthy at start")
	}
	before, budget := Usage()
	b, err := Consume([]byte("usage"))
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := Usage(); used != before+1 {
		t.Fatalf("used %d, want %d", used, before+1)
	}
	b.Destroy()
	b.Destroy()
	if used, _ := Usage(); used != before || budget <= 0 {
		t.Fatalf("used %d after destroy (budget %d)", used, budget)
	}
}
