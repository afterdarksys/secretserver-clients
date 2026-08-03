//go:build linux

package securemem

import "golang.org/x/sys/unix"

func hardenMapping(data []byte) error { return unix.Madvise(data, unix.MADV_DONTDUMP) }
