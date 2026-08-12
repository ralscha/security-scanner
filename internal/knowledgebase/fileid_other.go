//go:build !windows

package knowledgebase

import "os"

func fileIdentity(_ *os.File) (string, error) {
	return "", nil
}
