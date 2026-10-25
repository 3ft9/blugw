package blugw

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/3ft9/blugw/bthome"
)

func TestParseShelly(t *testing.T) {
	tests := []struct {
		name, data string
		mac        string // "" when absent
		model      uint16
	}{
		{"H&T", "0101000b03000ada778c8f3938", "38:39:8F:8C:77:DA", 0x0003},
		{"Motion", "0101000b05000ad51f42dec7b0", "B0:C7:DE:42:1F:D5", 0x0005},
		{"flags 0x0011", "0111000b03000ae22b9fb6c67c", "7C:C6:B6:9F:2B:E2", 0x0003},
		{"time beacon", "0dd791db6a000000009079c8699054dd6a100e0000", "", 0},
		{"stops at unknown type", "0b06000d0a010203040506", "", 0x0006},
		{"truncated MAC", "0101000a0102", "", 0},
		{"empty", "", "", 0},
	}
	for _, tc := range tests {
		data := unhex(t, tc.data)
		mac, model := parseShelly(data)
		got := ""
		if mac != (bthome.MAC{}) {
			got = mac.String()
		}
		if got != tc.mac || model != tc.model {
			t.Errorf("%s: got %q model %#04x, want %q model %#04x", tc.name, got, model, tc.mac, tc.model)
		}
		for i := range data {
			parseShelly(data[:i]) // must not panic
		}
	}
}

func TestHandle(t *testing.T) {
	const (
		// macOS CoreBluetooth addresses from live captures.
		ht     = "3bd38850-bb2a-9ebe-8832-f2305871f432"
		button = "518abb99-e63c-e043-fe03-c94f5275d5e3"
		other  = "00000000-0000-0000-0000-000000000001"
		beacon = "1F:00:00:00:00:01" // non-resolvable random address

		htMfr     = "0101000b03000ada778c8f3938" // MAC 38:39:8F:8C:77:DA, model 3
		buttonMfr = "0101000b01000aa43df52235b4" // MAC B4:35:22:F5:3D:A4, model 1
		buttonEnc = "450aeb84467f85ba0100003188788c"
		htPID9    = "44000901552e3745c300"
	)
	s := scanner{
		keys: map[bthome.MAC][]byte{
			{0xB4, 0x35, 0x22, 0xF5, 0x3D, 0xA4}: unhex(t, "90bffd73cb6b26ef58a7a8eba9232036"),
			{0x54, 0x48, 0xE6, 0x8F, 0x80, 0xA5}: unhex(t, "231d39c1d7cc1ab1aee224cd096db932"),
		},
		allow:    func(m bthome.MAC) bool { return m != bthome.MAC{0xA4, 0xC1, 0x38, 0, 0, 0x09} },
		devices:  map[string]*device{},
		counters: map[bthome.MAC]uint32{},
	}
	t0 := time.Date(2026, 10, 23, 18, 0, 0, 0, time.UTC)
	ms := time.Millisecond
	steps := []struct {
		name                 string
		at                   time.Duration // since t0
		addr, local, sd, mfr string
		want                 string // see render; "" when dropped
	}{
		{"service data before MAC is known", 0, ht, "", htPID9, "", ""},
		{"manufacturer data teaches MAC", 10 * ms, ht, "SBHT-003C", "", htMfr, ""},
		{"accepted once MAC is known", 20 * ms, ht, "", htPID9, "", `38:39:8F:8C:77:DA model=3 name="SBHT-003C" ctr=0 packet_id=9 battery=85 humidity=55 temperature=19.5`},
		{"repeat within 4 s", 1000 * ms, ht, "SBHT-003C", htPID9, htMfr, ""},
		{"repeat after 4 s", 4500 * ms, ht, "", htPID9, "", ""},
		{"packet ID jump after 4 s", 10000 * ms, ht, "", "4400ff01552e3745c300", "", `38:39:8F:8C:77:DA model=3 name="SBHT-003C" ctr=0 packet_id=255 battery=85 humidity=55 temperature=19.5`},
		{"packet ID wraps 255 to 0", 11000 * ms, ht, "", "44000001552e3745c300", "", `38:39:8F:8C:77:DA model=3 name="SBHT-003C" ctr=0 packet_id=0 battery=85 humidity=55 temperature=19.5`},
		{"stale packet ID within 4 s", 12000 * ms, ht, "", "4400fa01552e3745c300", "", ""},
		{"same packet ID after 4 s", 16000 * ms, ht, "", "44000001552e3745c300", "", `38:39:8F:8C:77:DA model=3 name="SBHT-003C" ctr=0 packet_id=0 battery=85 humidity=55 temperature=19.5`},
		{"unknown object yields partial reading", 17000 * ms, ht, "", "44000a0155fe0102", "", `38:39:8F:8C:77:DA model=3 name="SBHT-003C" ctr=0 packet_id=10 battery=85`},

		{"Linux address is the MAC", 0, "A4:C1:38:00:00:01", "", "4400a1016405945c002101", "", `A4:C1:38:00:00:01 model=0 name="" ctr=0 packet_id=161 battery=100 illuminance=237 motion=1`},
		{"stale service data re-sent much later", 30000 * ms, "A4:C1:38:00:00:01", "", "4400a1016405945c002101", "", ""},
		{"model from object 0xF0", 0, "A4:C1:38:00:00:02", "", "440001f00c00", "", `A4:C1:38:00:00:02 model=12 name="" ctr=0 packet_id=1 device_type_id=12`},
		{"unknown first object yields empty reading", 0, "A4:C1:38:00:00:03", "", "44fe01", "", `A4:C1:38:00:00:03 model=0 name="" ctr=0`},
		{"not allowed", 0, "A4:C1:38:00:00:09", "", "4400a1016405945c002101", "", ""},
		{"plaintext claiming a keyed MAC in the payload", 0, "11:22:33:44:55:66", "", "46a43df52235b4000701643a01", "", ""},

		{"encrypted, MAC from manufacturer data", 20000 * ms, button, "SBBT-002C", buttonEnc, buttonMfr, `B4:35:22:F5:3D:A4 model=1 name="SBBT-002C" ctr=442 packet_id=7 battery=100 button=1`},
		{"replayed from another address", 30000 * ms, other, "", buttonEnc, buttonMfr, ""},
		{"unencrypted from a MAC with a key", 31000 * ms, button, "", htPID9, "", ""},
		{"encrypted without a key", 0, "B4:35:22:F5:3D:A5", "", buttonEnc, "", ""},
		{"wrong key", 0, "54:48:E6:8F:80:A5", "", buttonEnc, "", ""},
		{"encrypted, MAC in payload differs from address", 1000 * ms, "C0:00:00:00:00:01", "", "43a5808fe64854f196c06ffb4900112233f08ecbde", "", `54:48:E6:8F:80:A5 model=0 name="" ctr=857870592 temperature=25.06 humidity=50.55`},
		{"same counter from another address", 2000 * ms, "54:48:E6:8F:80:A5", "", "41a47266c95f730011223378237214", "", ""},
		{"lower counter", 3000 * ms, "54:48:E6:8F:80:A5", "", "41e445f3c9962b332211006c7c4519", "", ""},

		{"time beacon", 0, beacon, "", "", "0dd791db6a000000009079c8699054dd6a100e0000", ""},
	}
	for _, st := range steps {
		r, ok := s.handle(advert{
			addr: st.addr,
			name: st.local,
			rssi: -60,
			time: t0.Add(st.at),
			data: unhex(t, st.sd),
			mfr:  unhex(t, st.mfr),
		})
		got := ""
		if ok {
			got = render(r)
			if !r.Time.Equal(t0.Add(st.at)) || r.RSSI != -60 {
				t.Errorf("%s: time %v rssi %d", st.name, r.Time, r.RSSI)
			}
		}
		if got != st.want {
			t.Errorf("%s:\n got  %s\n want %s", st.name, got, st.want)
		}
	}
	if s.devices[beacon] != nil {
		t.Error("time beacon added a device")
	}
}

func TestTimeBeacon(t *testing.T) {
	plug := time.Unix(0x6adb91d7, 0) // 2026-10-23 16:56:55 UTC
	tests := []struct {
		zone string
		at   time.Time
		want string // 0D, time, standard offset, DST start, DST end, DST shift
	}{
		// Captured from a Shelly Plug: DST 2026-03-29 01:00 to 2026-10-25 01:00 UTC.
		{"Europe/London", plug, "0dd791db6a000000009079c8699054dd6a100e0000"},
		{"UTC", plug, "0dd791db6a00000000000000000000000000000000"},
		{"Asia/Tokyo", plug, "0dd791db6a907e0000000000000000000000000000"},
		// -5 h; DST 2026-03-08 07:00 to 2026-11-01 06:00 UTC.
		{"America/New_York", plug, "0dd791db6ab0b9ffff701ead6960d5e66a100e0000"},
		// DST from 2026-10-03 16:00 UTC, and until 2026-04-04 16:00 UTC.
		{"Australia/Sydney", plug, "0dd791db6aa08c00008026c16a8035d169100e0000"},
		// 2027-01-01 01:00 local: 2027's DST from 2027-10-02 and until 2027-04-03.
		{"Australia/Sydney", time.Date(2026, 12, 31, 14, 0, 0, 0, time.UTC), "0de05f366ba08c00008008a16c8017b16b100e0000"},
	}
	for _, tc := range tests {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(timeBeacon(tc.at, loc)); got != tc.want {
			t.Errorf("%s at %v:\n got  %s\n want %s", tc.zone, tc.at, got, tc.want)
		}
	}
}

func TestScanTimeBeaconUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("supported on Linux")
	}
	// Must fail before touching the adapter.
	if err := Scan(context.Background(), Options{TimeBeacon: true}, nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

func render(r Reading) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s model=%d name=%q ctr=%d", r.MAC, r.Model, r.Name, r.Counter)
	for _, o := range r.Objects {
		fmt.Fprintf(&b, " %s=%g", o.Name(), o.Value)
	}
	return b.String()
}

// unhex decodes s, returning nil for "".
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
