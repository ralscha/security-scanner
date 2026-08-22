// Package userpath normalizes user-configured filesystem paths.
package userpath

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var reservedWindowsComponent = regexp.MustCompile(`(?i)^(?:con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\..*)?$`)

// ExpandHome expands a leading standalone ~ using the current user's home.
// Other-user forms such as ~alice are left as literal paths.
func ExpandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") && !strings.HasPrefix(path, `~\`) {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	if path == "~" {
		return home, nil
	}
	remainder := strings.TrimLeft(path[1:], `/\`)
	remainder = strings.ReplaceAll(remainder, `\`, "/")
	return filepath.Join(home, filepath.FromSlash(remainder)), nil
}

// WindowsUnsafeComponent returns the first path component that Windows can
// alias, reinterpret, or reject. The volume itself is not a path component.
func WindowsUnsafeComponent(path string) string {
	if volume := filepath.VolumeName(path); volume != "" {
		path = strings.TrimPrefix(path, volume)
	}
	for component := range strings.FieldsFuncSeq(path, func(r rune) bool { return r == '/' || r == '\\' }) {
		if component == "" || component == "." {
			continue
		}
		if strings.HasSuffix(component, " ") || strings.HasSuffix(component, ".") || reservedWindowsComponent.MatchString(component) {
			return component
		}
		for _, r := range component {
			if r <= 0x1f || strings.ContainsRune(`<>:"|?*`, r) {
				return component
			}
		}
	}
	return ""
}

// ValidateWindowsPath rejects paths whose components have ambiguous Windows
// filesystem interpretations. Other platforms retain their native path rules.
func ValidateWindowsPath(path string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	if component := WindowsUnsafeComponent(path); component != "" {
		return fmt.Errorf("path contains Windows-ambiguous component %q", component)
	}
	return nil
}

// ResolveExisting expands a user path and returns its canonical existing path.
func ResolveExisting(path string) (string, error) {
	expanded, err := ExpandHome(path)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	if err := ValidateWindowsPath(absolute); err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	if err := ValidateWindowsPath(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}

// ResolveIfExists canonicalizes an existing path and otherwise returns its
// absolute spelling. It is useful for matching durable records after a target
// has been moved or deleted.
func ResolveIfExists(path string) (string, error) {
	expanded, err := ExpandHome(path)
	if err != nil {
		return "", err
	}
	absolute, err := filepath.Abs(expanded)
	if err != nil {
		return "", err
	}
	if err := ValidateWindowsPath(absolute); err != nil {
		return "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if os.IsNotExist(err) {
		return absolute, nil
	}
	if err != nil {
		return "", err
	}
	if err := ValidateWindowsPath(canonical); err != nil {
		return "", err
	}
	return canonical, nil
}
