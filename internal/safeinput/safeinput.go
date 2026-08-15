// Package safeinput reads user-selected input files without accepting pipes,
// devices, directories, or symbolic-link substitutions.
package safeinput

import (
	"fmt"
	"io"
	"os"
)

// ReadRegularFile reads path only when it remains the same regular file from
// selection through the completed read.
func ReadRegularFile(path string) (_ []byte, err error) {
	selected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !selected.Mode().IsRegular() || selected.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("input must be a non-symlink regular file: %s", path)
	}
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(selected, opened) {
		return nil, fmt.Errorf("input must remain the selected regular file: %s", path)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !named.Mode().IsRegular() || named.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(opened, after) || !os.SameFile(after, named) || after.Size() != int64(len(data)) {
		return nil, fmt.Errorf("input changed while reading: %s", path)
	}
	return data, nil
}
