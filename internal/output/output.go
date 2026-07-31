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

// Guard pins a private directory to the filesystem object that was prepared.
// Validate must be called immediately before every security-sensitive use so a
// renamed or replaced path cannot silently substitute a different artifact tree.
type Guard struct {
	path string
	info os.FileInfo
}

func (g *Guard) Path() string { return g.path }

func (g *Guard) Validate() error {
	if g == nil || g.info == nil || strings.TrimSpace(g.path) == "" {
		return fmt.Errorf("private directory guard is not initialized")
	}
	info, err := os.Lstat(g.path)
	if err != nil {
		return fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private directory must remain a non-symlink directory: %s", g.path)
	}
	canonical, err := filepath.EvalSymlinks(g.path)
	if err != nil {
		return fmt.Errorf("resolve private directory: %w", err)
	}
	if !sameCanonicalPath(g.path, canonical) || !os.SameFile(g.info, info) {
		return fmt.Errorf("private directory was replaced after preparation: %s", g.path)
	}
	if err := validatePrivateDirectory(info, g.path); err != nil {
		return err
	}
	return validateSecureAncestry(g.path)
}

func StateDir() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("SECURITY_SCANNER_STATE_DIR")); configured != "" {
		return ResolvePath(configured)
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user configuration directory: %w", err)
	}
	return ResolvePath(filepath.Join(root, "security-scanner"))
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

func Validate(_ context.Context, _, destination string, archiveExisting bool) (string, error) {
	absDestination, err := ResolvePath(destination)
	if err != nil {
		return "", err
	}
	if err := validateSecureAncestry(absDestination); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(absDestination)
	if os.IsNotExist(err) {
		return absDestination, nil
	}
	if err != nil {
		return "", fmt.Errorf("inspect output directory: %w", err)
	}
	info, err := os.Lstat(absDestination)
	if err != nil {
		return "", fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("output directory must be a non-symlink directory: %s", absDestination)
	}
	if err := validatePrivateDirectoryForPlanning(info, absDestination); err != nil {
		return "", err
	}
	if len(entries) > 0 && !archiveExisting {
		return "", fmt.Errorf("output directory is not empty; choose another path or use --archive-existing")
	}
	return absDestination, nil
}

// ResolvePath returns an absolute path beneath its canonical existing ancestor.
// The final path itself may not be a symlink.
func ResolvePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	if strings.IndexFunc(absPath, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029'
	}) >= 0 {
		return "", fmt.Errorf("path must not contain control or line-separator characters")
	}
	if info, statErr := os.Lstat(absPath); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("path must not be a symbolic link: %s", absPath)
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect path: %w", statErr)
	}
	return resolveAvailablePath(absPath)
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
	absDestination, err := ResolvePath(destination)
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

// PreparePrivateDir creates a scan/export directory privately and pins its
// identity. Existing POSIX directories must already be private; Windows ACLs
// are explicitly replaced because os.FileMode does not secure them.
func PreparePrivateDir(path string) (*Guard, error) {
	return preparePrivateDir(path, false)
}

// EnsurePrivateDir creates or tightens a scanner-owned state directory.
func EnsurePrivateDir(path string) (*Guard, error) {
	return preparePrivateDir(path, true)
}

// OpenPrivateDir validates and pins an existing private directory without
// changing it.
func OpenPrivateDir(path string) (*Guard, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, fmt.Errorf("inspect private directory: %w", err)
	}
	guard := &Guard{path: resolved, info: info}
	if err := guard.Validate(); err != nil {
		return nil, err
	}
	return guard, nil
}

func preparePrivateDir(path string, tightenExisting bool) (*Guard, error) {
	resolved, err := ResolvePath(path)
	if err != nil {
		return nil, err
	}
	created, err := createMissingDirectories(resolved)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, fmt.Errorf("inspect private directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private path must be a non-symlink directory: %s", resolved)
	}
	if err := preparePrivateDirectory(resolved, created, tightenExisting); err != nil {
		return nil, err
	}
	info, err = os.Lstat(resolved)
	if err != nil {
		return nil, fmt.Errorf("inspect prepared private directory: %w", err)
	}
	guard := &Guard{path: resolved, info: info}
	if err := guard.Validate(); err != nil {
		return nil, err
	}
	return guard, nil
}

func createMissingDirectories(path string) (bool, error) {
	missing := make([]string, 0)
	current := path
	for {
		info, err := os.Lstat(current)
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return false, fmt.Errorf("private path ancestor must be a non-symlink directory: %s", current)
			}
			break
		}
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("inspect private path ancestor: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, fmt.Errorf("private path has no existing ancestor: %s", path)
		}
		missing = append(missing, current)
		current = parent
	}
	for i := len(missing) - 1; i >= 0; i-- {
		created := false
		if err := os.Mkdir(missing[i], 0o700); err == nil {
			created = true
		} else if !os.IsExist(err) {
			return false, fmt.Errorf("create private directory: %w", err)
		}
		info, err := os.Lstat(missing[i])
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("created private path is not a non-symlink directory: %s", missing[i])
		}
		if err := preparePrivateDirectory(missing[i], created, true); err != nil {
			return false, err
		}
	}
	return len(missing) > 0, nil
}

// SecurePrivateFile applies and verifies the platform's private-file policy.
func SecurePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect private file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("private file must be a non-symlink regular file: %s", path)
	}
	if err := preparePrivateFile(path); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect secured private file: %w", err)
	}
	return validatePrivateFile(info, path)
}

// ReadPrivateFile reads one regular private file from a pinned directory and
// rejects replacements before and after the read.
func ReadPrivateFile(guard *Guard, name string) ([]byte, error) {
	if guard == nil {
		return nil, fmt.Errorf("private directory guard is required")
	}
	if filepath.Base(name) != name || name == "." || name == "" {
		return nil, fmt.Errorf("private file name must be a base name")
	}
	if err := guard.Validate(); err != nil {
		return nil, err
	}
	path := filepath.Join(guard.path, name)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("private artifact must be a non-symlink regular file: %s", path)
	}
	if err := validatePrivateFile(before, path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("private artifact was replaced while reading: %s", path)
	}
	if err := guard.Validate(); err != nil {
		return nil, err
	}
	return data, nil
}

// WritePrivateFileAtomic publishes one private file inside a pinned directory.
func WritePrivateFileAtomic(guard *Guard, name string, data []byte) (err error) {
	if guard == nil {
		return fmt.Errorf("private directory guard is required")
	}
	if filepath.Base(name) != name || name == "." || name == "" {
		return fmt.Errorf("private file name must be a base name")
	}
	if err := guard.Validate(); err != nil {
		return err
	}
	temp, err := os.CreateTemp(guard.path, ".private-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		removeErr := os.Remove(tempPath)
		if err == nil && removeErr != nil && !os.IsNotExist(removeErr) {
			err = removeErr
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := SecurePrivateFile(tempPath); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := guard.Validate(); err != nil {
		return err
	}
	destination := filepath.Join(guard.path, name)
	if err := os.Rename(tempPath, destination); err == nil {
		return nil
	}
	if err := guard.Validate(); err != nil {
		return err
	}
	if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := guard.Validate(); err != nil {
		return err
	}
	return os.Rename(tempPath, destination)
}

func Prepare(destination string, archiveExisting bool, now time.Time) (string, error) {
	guard, err := PreparePrivateDir(destination)
	if err != nil {
		return "", fmt.Errorf("prepare output directory: %w", err)
	}
	destination = guard.Path()
	entries, err := os.ReadDir(destination)
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
	if err := guard.Validate(); err != nil {
		return "", fmt.Errorf("revalidate output before archiving: %w", err)
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
