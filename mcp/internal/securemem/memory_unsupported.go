//go:build !darwin && !linux

package securemem

import "fmt"

func allocLocked(_ int) ([]byte, error) {
	return nil, fmt.Errorf("locked memory is not implemented on this platform")
}

func releaseLocked(_ []byte) error { return nil }
