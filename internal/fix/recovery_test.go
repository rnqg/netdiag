package fix

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryScanPreservesActiveSession(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("TMP", root)
	t.Setenv("TEMP", root)
	dir, err := os.MkdirTemp(root, "net-repair-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	r := Record{Format: "netdiag-recovery-v1", OwnerPID: os.Getpid(), Created: time.Now(), Nonce: "test-nonce"}
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	Recoveries()
	if _, err = os.Stat(path); err != nil {
		t.Fatal("active request removed")
	}
	r.OwnerPID = 0
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	Recoveries()
	if _, err = os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("inactive unprepared session not cleaned")
	}
}

func TestRecoveryRejectsInvalidNonceAndRetainsFailedRollback(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TMPDIR", root)
	t.Setenv("TMP", root)
	t.Setenv("TEMP", root)
	dir, err := os.MkdirTemp(root, "net-repair-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	r := Record{Format: "netdiag-recovery-v1", Nonce: "correct", Prepared: true, Finished: true, Failure: "concurrent settings changed"}
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	if _, err = load(path, "wrong"); err == nil {
		t.Fatal("invalid nonce accepted")
	}
	pending := Recoveries()
	if len(pending) != 1 || pending[0] != path {
		t.Fatal("failed rollback hidden or deleted")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
