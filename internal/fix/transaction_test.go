package fix

import (
	"context"
	"errors"
	"testing"
)

type fakeAdapter struct {
	state  State
	writes int
	fail   bool
}

func (a *fakeAdapter) Read(context.Context, string) (State, error) { return a.state, nil }
func (a *fakeAdapter) Write(_ context.Context, s State) error {
	if a.fail {
		return errors.New("write failure")
	}
	a.state = s
	a.writes++
	return nil
}

func fixtureStates() (State, State) {
	a := State{Interface: "test", DNS: []string{"192.0.2.1"}}
	b := State{Interface: "test", DNS: []string{"192.0.2.2"}}
	return a, b
}

func TestTransactionKeepsOnlyVerifiedConfirmedChange(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: before}
	prepared := false
	verified := false
	kept, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(x, y State) error {
		if !Same(x, before) || !Same(y, desired) {
			t.Fatal("wrong snapshot")
		}
		prepared = true
		return nil
	}, Verify: func(context.Context) error { verified = true; return nil }, Keep: func(context.Context) bool { return true }})
	if err != nil || !kept || !prepared || !verified || !Same(a.state, desired) || a.writes != 1 {
		t.Fatalf("%v %v %+v", kept, err, a)
	}
}

func TestTransactionRollsBackFailedVerificationAndDeclinedKeep(t *testing.T) {
	for _, failVerify := range []bool{false, true} {
		t.Run(map[bool]string{false: "declined", true: "failed"}[failVerify], func(t *testing.T) {
			before, desired := fixtureStates()
			a := &fakeAdapter{state: before}
			kept, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(State, State) error { return nil }, Verify: func(context.Context) error {
				if failVerify {
					return errors.New("verification failed")
				}
				return nil
			}, Keep: func(context.Context) bool { return false }})
			if kept || !Same(a.state, before) || a.writes != 2 {
				t.Fatalf("rollback failed: %v %v %+v", kept, err, a)
			}
			if failVerify && err == nil {
				t.Fatal("verification failure hidden")
			}
		})
	}
}

func TestConcurrentUserChangeIsPreserved(t *testing.T) {
	before, desired := fixtureStates()
	user := State{Interface: "test", DNS: []string{"192.0.2.3"}}
	a := &fakeAdapter{state: before}
	kept, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(State, State) error { return nil }, Verify: func(context.Context) error { a.state = user; return errors.New("changed") }, Keep: func(context.Context) bool { return false }})
	if kept || err == nil || !Same(a.state, user) || a.writes != 1 {
		t.Fatalf("user settings overwritten: %+v", a)
	}
}

func TestSnapshotFailurePreventsMutation(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: before}
	_, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(State, State) error { return errors.New("disk full") }})
	if err == nil || a.writes != 0 {
		t.Fatal("mutation without recoverable snapshot")
	}
}

func TestChangedBaselinePreventsMutation(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: desired}
	_, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(State, State) error { t.Fatal("snapshot should not run"); return nil }})
	if err == nil || a.writes != 0 {
		t.Fatal("stale baseline accepted")
	}
}

func TestRestoreIsIdempotent(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: desired}
	for i := 0; i < 2; i++ {
		if err := Restore(context.Background(), a, before, desired); err != nil {
			t.Fatal(err)
		}
	}
	if a.writes != 1 {
		t.Fatal(a.writes)
	}
}

func TestChangeDuringConfirmationIsNotReportedAsApplied(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: before}
	user := State{Interface: "test", DNS: []string{"192.0.2.3"}}
	kept, err := Transact(context.Background(), a, before, desired, TransactionHooks{Prepared: func(State, State) error { return nil }, Keep: func(context.Context) bool { a.state = user; return true }})
	if kept || err == nil || !Same(a.state, user) {
		t.Fatal("concurrent confirmation change accepted")
	}
}

func TestCancellationDuringConfirmationRollsBack(t *testing.T) {
	before, desired := fixtureStates()
	a := &fakeAdapter{state: before}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kept, err := Transact(ctx, a, before, desired, TransactionHooks{Prepared: func(State, State) error { return nil }, Keep: func(context.Context) bool { cancel(); return true }})
	if kept || err == nil || !Same(a.state, before) {
		t.Fatal("cancellation left the change applied")
	}
}
