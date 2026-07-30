package output

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func StateDir() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("SECURITY_SCANNER_STATE_DIR")); configured != "" {
		return filepath.Abs(configured)
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user configuration directory: %w", err)
	}
	return filepath.Join(root, "security-scanner"), nil
}

func DefaultScanDir(target string, started time.Time) (string, error) {
	state, err := StateDir()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(pathKey(target)))
	return filepath.Join(state, "scans", fmt.Sprintf("%x", digest[:8]), started.UTC().Format("20060102T150405.000000000Z")), nil
}

func pathKey(path string) string {
	key := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(key)
	}
	return key
}

func Validate(_ context.Context, _, destination string, archiveExisting bool) error {
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	absDestination, err = resolveAvailablePath(absDestination)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(absDestination)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if len(entries) > 0 && !archiveExisting {
		return fmt.Errorf("output directory is not empty; choose another path or use --archive-existing")
	}
	return nil
}

func resolveAvailablePath(path string) (string, error) {
	missing := make([]string, 0)
	current := filepath.Clean(path)
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("resolve output path: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("resolve output path: no existing ancestor for %s", path)
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}

func ValidateBoundary(ctx context.Context, target, destination string) error {
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolve output directory: %w", err)
	}
	boundary := worktreeRoot(ctx, target)
	inside, err := isWithin(boundary, absDestination)
	if err != nil {
		return err
	}
	if inside {
		return fmt.Errorf("output directory must be outside scanned root and enclosing worktree: %s", boundary)
	}
	return nil
}

func Prepare(destination string, archiveExisting bool, now time.Time) (string, error) {
	entries, err := os.ReadDir(destination)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect output directory: %w", err)
	}
	if len(entries) == 0 {
		return "", nil
	}
	if !archiveExisting {
		return "", fmt.Errorf("output directory is not empty; choose another path or use --archive-existing")
	}
	base := destination + ".archive-" + now.UTC().Format("20060102T150405Z")
	archive := base
	for sequence := 1; ; sequence++ {
		if _, err := os.Lstat(archive); os.IsNotExist(err) {
			break
		} else if err != nil {
			return "", fmt.Errorf("inspect archive destination: %w", err)
		}
		archive = fmt.Sprintf("%s-%d", base, sequence)
	}
	if err := os.Rename(destination, archive); err != nil {
		return "", fmt.Errorf("archive existing output: %w", err)
	}
	return archive, nil
}

func worktreeRoot(ctx context.Context, target string) string {
	command := exec.CommandContext(ctx, "git", "-C", target, "rev-parse", "--show-toplevel")
	output, err := command.Output()
	if err != nil {
		return target
	}
	root := strings.TrimSpace(string(output))
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		return resolved
	}
	return root
}

func isWithin(root, candidate string) (bool, error) {
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(candidate))
	if err != nil {
		return false, fmt.Errorf("compare output directory with worktree: %w", err)
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}
