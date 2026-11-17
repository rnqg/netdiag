package diag

import (
	"github.com/m-lab/ndt7-client-go/spec"
	"testing"
)

func TestNDTUploadUsesReceiverAndLabelsUnacknowledgedFallback(t *testing.T) {
	for _, ack := range []bool{true, false} {
		ch := make(chan spec.Measurement, 2)
		ch <- spec.Measurement{Origin: spec.OriginClient, AppInfo: &spec.AppInfo{NumBytes: 1000000, ElapsedTime: 1000000}}
		if ack {
			ch <- spec.Measurement{Origin: spec.OriginServer, AppInfo: &spec.AppInfo{NumBytes: 250000, ElapsedTime: 1000000}}
		}
		close(ch)
		m := Measurement{Data: map[string]any{}}
		populateNDT(&m, "upload", ch)
		if ack {
			if m.Data["mbps"] != 2.0 || m.Status != "ok" {
				t.Fatal(m)
			}
		} else {
			if m.Status != "partial" || m.Data["measurement_source"] != "client_sender_unacknowledged" {
				t.Fatal(m)
			}
		}
	}
}
