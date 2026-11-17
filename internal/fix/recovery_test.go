package fix

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

var ownershipHelperPath = flag.String("snapshot-helper", "", "")

func TestRecoveryOwnershipHelper(t *testing.T) {
	if *ownershipHelperPath == "" {
		return
	}
	r, err := load(*ownershipHelperPath, "owner-test")
	if err != nil {
		t.Fatal(err)
	}
	r.Finished = true
	if err = save(*ownershipHelperPath, r); err != nil {
		t.Fatal(err)
	}
}

func TestElevatedSnapshotRemainsReadableByCaller(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getenv("NETDIAG_TEST_ELEVATION") != "1" {
		t.Skip("optional Unix elevation test")
	}
	if out, err := exec.Command("sudo", "-n", "true").CombinedOutput(); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("CI must exercise snapshot ownership with sudo: %v %s", err, out)
		}
		t.Skip("passwordless sudo unavailable: " + strings.TrimSpace(string(out)))
	}
	dir, err := os.MkdirTemp(t.TempDir(), "net-repair-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	r := Record{Format: "netdiag-recovery-v1", Nonce: "owner-test", OwnerPID: os.Getpid()}
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sudo", "-n", "--", exe, "-test.run=^TestRecoveryOwnershipHelper$", "-snapshot-helper="+path).CombinedOutput()
	if err != nil {
		t.Fatalf("elevated helper: %v %s", err, out)
	}
	result, err := load(path, "owner-test")
	if err != nil || !result.Finished {
		t.Fatalf("caller cannot read completed snapshot: %+v %v", result, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: %v %v", info, err)
	}
}

func TestSnapshotReplacementKeepsPrivatePermissions(t *testing.T) {
	dir, err := os.MkdirTemp(t.TempDir(), "net-repair-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	r := Record{Format: "netdiag-recovery-v1", Nonce: "replace"}
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	r.Finished = true
	if err = save(path, r); err != nil {
		t.Fatal(err)
	}
	result, err := load(path, r.Nonce)
	if err != nil || !result.Finished {
		t.Fatal(result, err)
	}
}

func TestExpiredRepairGuardRestoresOrPreservesSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name              string
		external, failing bool
	}{
		{name: "restored"}, {name: "external change", external: true}, {name: "write failure", failing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := os.MkdirTemp(t.TempDir(), "net-repair-")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "state.json")
			before, written := fixtureStates()
			current := written
			if tc.external {
				current = State{Interface: written.Interface, DNS: []string{"192.0.2.9"}}
			}
			adapter := &fakeAdapter{state: current, fail: tc.failing}
			r := Record{Format: "netdiag-recovery-v1", Nonce: "guard", Prepared: true, Before: before, Written: written, Deadline: time.Now().Add(-time.Second)}
			if err := save(path, r); err != nil {
				t.Fatal(err)
			}
			err = guard(context.Background(), path, r.Nonce, adapter)
			if !tc.external && !tc.failing {
				if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) || err != nil || !Same(adapter.state, before) {
					t.Fatalf("restoration did not close the session: %v %v %+v", err, statErr, adapter.state)
				}
			} else {
				result, loadErr := load(path, r.Nonce)
				if err == nil || loadErr != nil || !result.Finished || result.Failure == "" || !Same(adapter.state, current) {
					t.Fatalf("unsafe rollback was not recoverable: %v %v %+v", err, loadErr, result)
				}
			}
		})
	}
}
