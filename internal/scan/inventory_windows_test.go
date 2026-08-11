//go:build windows

package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBuildInventorySkipsWindowsJunction(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeTestFile(t, outside, "outside.go", []byte("package outside\n"))
	junction := filepath.Join(root, "linked")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("create test junction: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })

	inv, err := BuildInventory(root, InventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Files) != 1 || inv.Files[0].Path != "linked" || inv.Files[0].Reviewable || inv.Files[0].SkipReason != "special_file" {
		t.Fatalf("unexpected junction inventory: %#v", inv.Files)
	}
}
