//go:build darwin || linux

package securemem

import "golang.org/x/sys/unix"

func allocLocked(size int) ([]byte, error) {
	data, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	if err := unix.Mlock(data); err != nil {
		_ = unix.Munmap(data)
		return nil, err
	}
	if err := hardenMapping(data); err != nil {
		_ = unix.Munlock(data)
		_ = unix.Munmap(data)
		return nil, err
	}
	return data, nil
}

func releaseLocked(data []byte) error {
	unlockErr := unix.Munlock(data)
	unmapErr := unix.Munmap(data)
	if unlockErr != nil {
		return unlockErr
	}
	return unmapErr
}
