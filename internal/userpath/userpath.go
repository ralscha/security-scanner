// Package userpath normalizes user-configured filesystem paths.
package userpath

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
