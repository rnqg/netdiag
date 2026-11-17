package diag

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

func wifiWindows(_ context.Context, m Measurement) Measurement {
	dll := windows.NewLazySystemDLL("wlanapi.dll")
	open := dll.NewProc("WlanOpenHandle")
	closeHandle := dll.NewProc("WlanCloseHandle")
	enumerate := dll.NewProc("WlanEnumInterfaces")
	query := dll.NewProc("WlanQueryInterface")
	free := dll.NewProc("WlanFreeMemory")
	for _, proc := range []*windows.LazyProc{open, closeHandle, enumerate, query, free} {
		if proc.Find() != nil {
			return m
		}
	}
	var version uint32
	var handle windows.Handle
	status, _, _ := open.Call(2, 0, uintptr(unsafe.Pointer(&version)), uintptr(unsafe.Pointer(&handle)))
	if status != 0 {
		return m
	}
	defer closeHandle.Call(uintptr(handle), 0)
	var list unsafe.Pointer
	status, _, _ = enumerate.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&list)))
	if status != 0 || list == nil {
		return m
	}
	defer free.Call(uintptr(list))
	count := *(*uint32)(list)
	if count > 64 {
		return m
	}
	for index := uint32(0); index < count; index++ {
		entry := unsafe.Add(list, 8+uintptr(index)*532)
		state := *(*uint32)(unsafe.Add(entry, 528))
		if state != 1 {
			continue
		}
		var size, opcode uint32
		var data unsafe.Pointer
		status, _, _ = query.Call(uintptr(handle), uintptr(entry), 7, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&opcode)))
		if status != 0 || data == nil {
			continue
		}
		if size >= 588 {
			m.Data["signal_quality_percent"] = *(*uint32)(unsafe.Add(data, 576))
			m.Data["rx_mbps"] = float64(*(*uint32)(unsafe.Add(data, 580))) / 1000
			m.Data["tx_mbps"] = float64(*(*uint32)(unsafe.Add(data, 584))) / 1000
			m.Status = "ok"
			m.Reason = ""
		}
		free.Call(uintptr(data))
		data = nil
		status, _, _ = query.Call(uintptr(handle), uintptr(entry), 8, 0, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&data)), uintptr(unsafe.Pointer(&opcode)))
		if status == 0 && data != nil {
			if size >= 4 {
				m.Data["channel"] = *(*uint32)(data)
			}
			free.Call(uintptr(data))
		}
		return m
	}
	return m
}
