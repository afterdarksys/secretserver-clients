//go:build !linux && !darwin

package securemem

// Without an RLIMIT_MEMLOCK to read, the adapter uses its default cap.
func memlockLimit() (uint64, bool) { return 0, false }
