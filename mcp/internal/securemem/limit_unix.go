//go:build linux || darwin

package securemem

import "golang.org/x/sys/unix"

// memlockLimit returns the soft RLIMIT_MEMLOCK in bytes and whether it is
// finite. A failed query is reported as a zero limit, so nothing is locked.
func memlockLimit() (uint64, bool) {
	var r unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &r); err != nil {
		return 0, true
	}
	if r.Cur == unix.RLIM_INFINITY {
		return 0, false
	}
	return r.Cur, true
}
