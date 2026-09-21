//go:build unix

package main

// fdlimit.go — lift the soft RLIMIT_NOFILE to the hard limit at startup.
// The hub holds ~2 FDs per connection (client + server socket); on a
// default Linux soft limit of 1024 the process dies around ~500 in-process
// connections. Best-effort: on failure run() logs and continues.

import "syscall"

func raiseFileLimit() (soft, hard uint64, raised bool, err error) {
	var rl syscall.Rlimit
	if err = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0, 0, false, err
	}
	soft, hard = rl.Cur, rl.Max
	if rl.Cur >= rl.Max {
		return soft, hard, false, nil
	}
	rl.Cur = rl.Max
	if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return soft, hard, false, err
	}
	return rl.Cur, hard, true, nil
}
