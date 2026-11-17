package fix

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func isElevated() bool { return os.Geteuid() == 0 }
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
func ownedDirectory(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
func elevate(ctx context.Context, exe string, args []string) error {
	var cmd *exec.Cmd
	if isElevated() {
		cmd = exec.CommandContext(ctx, exe, args...)
	} else {
		cmd = exec.CommandContext(ctx, "sudo", append([]string{"--", exe}, args...)...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
func ignoreInterrupts()    { signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM) }

func preserveOwner(f *os.File, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("invalid recovery file")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("recovery owner unavailable")
	}
	if owner.Uid == uint32(os.Geteuid()) {
		return nil
	}
	return f.Chown(int(owner.Uid), int(owner.Gid))
}
