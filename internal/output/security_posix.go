//go:build linux || darwin

package output

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func preparePrivateDirectory(path string, created, tightenExisting bool) error {
	if created || tightenExisting {
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect private directory owner: %w", err)
		}
		if err := requireCurrentOwner(info, path); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("make directory private: %w", err)
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return validatePrivateDirectory(info, path)
}

func preparePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := requireCurrentOwner(info, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("make file private: %w", err)
	}
	return nil
}

func validatePrivateDirectoryForPlanning(info os.FileInfo, path string) error {
	return validatePrivateDirectory(info, path)
}

func validatePrivateDirectory(info os.FileInfo, path string) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory must be a non-symlink directory: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("scan output directory must not be accessible to other users (chmod 700): %s", path)
	}
	return requireCurrentOwner(info, path)
}

func validatePrivateFile(info os.FileInfo, path string) error {
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private file must be a non-symlink regular file: %s", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private file must not be accessible to other users (chmod 600): %s", path)
	}
	return requireCurrentOwner(info, path)
}

func requireCurrentOwner(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect filesystem owner for %s", path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("private path must be owned by the current user: %s", path)
	}
	return nil
}

func validateSecureAncestry(path string) error {
	current := filepath.Dir(filepath.Clean(path))
	for {
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			parent := filepath.Dir(current)
			if parent == current {
				return fmt.Errorf("scan output path has no existing parent: %s", path)
			}
			current = parent
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect scan output parent: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("scan output parent must be a non-symlink directory: %s", current)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("inspect scan output parent owner: %s", current)
		}
		if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("scan output parent must have a trusted owner: %s", current)
		}
		if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("scan output parent must not be group- or world-writable without the sticky bit: %s", current)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func sameCanonicalPath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}
