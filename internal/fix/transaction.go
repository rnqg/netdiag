package fix

import (
	"context"
	"errors"
	"reflect"
	"time"
)

func Same(a, b State) bool { return reflect.DeepEqual(a, b) }

func Restore(ctx context.Context, a Adapter, before, written State) error {
	current, err := a.Read(ctx, written.Interface)
	if err != nil {
		return err
	}
	if Same(current, before) {
		return nil
	}
	if !Same(current, written) {
		return errors.New("настройки изменены извне: автоматический откат остановлен, чтобы не перезаписать чужие изменения")
	}
	if err = a.Write(ctx, before); err != nil {
		return err
	}
	current, err = a.Read(ctx, before.Interface)
	if err != nil {
		return err
	}
	if !Same(current, before) {
		return errors.New("восстановление настроек не подтверждено")
	}
	return nil
}

type TransactionHooks struct {
	Prepared func(State, State) error
	Verify   func(context.Context) error
	Keep     func(context.Context) bool
}

func Transact(ctx context.Context, a Adapter, before, desired State, h TransactionHooks) (bool, error) {
	current, err := a.Read(ctx, before.Interface)
	if err != nil {
		return false, err
	}
	if !Same(current, before) {
		return false, errors.New("исходное состояние изменилось; повторите диагностику")
	}
	if err = h.Prepared(before, desired); err != nil {
		return false, err
	}
	err = a.Write(ctx, desired)
	if err == nil {
		current, err = a.Read(ctx, desired.Interface)
		if err == nil && !Same(current, desired) {
			err = errors.New("изменение настроек не подтверждено")
		}
	}
	if err == nil && h.Verify != nil {
		err = h.Verify(ctx)
	}
	if err == nil && h.Keep != nil && h.Keep(ctx) {
		current, readErr := a.Read(ctx, desired.Interface)
		err = readErr
		if err == nil && !Same(current, desired) {
			err = errors.New("настройки изменились во время подтверждения; стороннее состояние сохранено")
		}
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			return true, nil
		}
	}
	rollbackCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	defer stop()
	rollbackErr := Restore(rollbackCtx, a, before, desired)
	if rollbackErr != nil {
		return false, rollbackErr
	}
	if err != nil {
		return false, err
	}
	return false, nil
}
