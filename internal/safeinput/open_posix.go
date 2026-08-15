//go:build linux || darwin

package safeinput

import (
	"os"
	"syscall"
)

func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
