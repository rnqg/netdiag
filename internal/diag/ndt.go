package diag

import "github.com/m-lab/ndt7-client-go/spec"

func populateNDT(m *Measurement, phase string, ch <-chan spec.Measurement) {
	var local, remote *spec.AppInfo
	for event := range ch {
		if event.AppInfo != nil && event.AppInfo.NumBytes >= 0 && event.AppInfo.ElapsedTime > 0 {
			value := *event.AppInfo
			if event.Origin == spec.OriginClient {
				local = &value
			}
			if event.Origin == spec.OriginServer {
				remote = &value
			}
		}
		if event.Origin == spec.OriginServer && event.TCPInfo != nil {
			m.Data["server_tcp_info"] = event.TCPInfo
		}
	}
	chosen := local
	m.Data["measurement_source"] = "client_receiver"
	if phase == "upload" {
		chosen = remote
		m.Data["measurement_source"] = "server_receiver"
		if chosen == nil {
			chosen = local
			m.Data["measurement_source"] = "client_sender_unacknowledged"
		}
	}
	if local != nil {
		m.Data["client_bytes"] = local.NumBytes
		m.Data["client_elapsed_us"] = local.ElapsedTime
	}
	if remote != nil {
		m.Data["server_bytes"] = remote.NumBytes
		m.Data["server_elapsed_us"] = remote.ElapsedTime
	}
	if chosen != nil && chosen.NumBytes > 0 {
		m.Status = "ok"
		m.Reason = ""
		m.Data["mbps"] = float64(chosen.NumBytes) * 8 / float64(chosen.ElapsedTime)
		m.Data["bytes"] = chosen.NumBytes
		m.Data["elapsed_us"] = chosen.ElapsedTime
		if phase == "upload" && remote == nil {
			m.Status = "partial"
			m.Reason = "upload_not_acknowledged"
		}
	} else {
		m.Status = "failed"
		m.Reason = "ndt7_no_measurements"
	}
	m.Data["completion_scope"] = "NDT7 library closes its measurement channel; transport close status is not exposed"
}
