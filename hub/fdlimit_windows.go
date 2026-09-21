//go:build windows

package main

// fdlimit_windows.go — no rlimit on Windows; the soft-limit raise is a
// unix-only concern (Windows handles are not FD-limited the same way).

func raiseFileLimit() (soft, hard uint64, raised bool, err error) {
	return 0, 0, false, nil
}
