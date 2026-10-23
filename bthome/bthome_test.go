package bthome

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const (
	specKey   = "231d39c1d7cc1ab1aee224cd096db932"
	specMAC   = "54:48:E6:8F:80:A5"
	shellyKey = "90bffd73cb6b26ef58a7a8eba9232036"
	shellyMAC = "B4:35:22:F5:3D:A4"
)

func TestDecode(t *testing.T) {
	tests := []struct {
		name, data, mac, key string
		want                 string // see render
		err                  error
	}{
		// Encryption vectors from bthome.io/encryption and bthome-ble tests.
		{"bthome.io example", "41e445f3c9962b332211006c7c4519", specMAC, specKey, specMAC + " ctr=1122867 temperature=25.06°C humidity=50.55%", nil},
		{"bthome-ble ex1", "41a47266c95f730011223378237214", specMAC, specKey, specMAC + " ctr=857870592 temperature=25.06°C humidity=50.55%", nil},
		{"bthome-ble ex2", "4187b90011223372b0231f", specMAC, specKey, specMAC + " ctr=857870592 motion=1", nil},
		{"Shelly Button1 encrypted", "450aeb84467f85ba0100003188788c", shellyMAC, shellyKey, shellyMAC + " ctr=442 trigger packet_id=7 battery=100% button=1:press", nil},
		{"MAC in payload, encrypted", "43a5808fe64854f196c06ffb4900112233f08ecbde", "", specKey, specMAC + " ctr=857870592 temperature=25.06°C humidity=50.55%", nil},
		{"MAC in payload", "42b2188d38c1a404138a01", "", "", "A4:C1:38:8D:18:B2 pressure=1008.83hPa", nil},
		{"wrong key", "450aeb84467f85ba0100003188788c", shellyMAC, specKey, shellyMAC + " ctr=442 trigger", ErrDecrypt},
		{"wrong MAC", "450aeb84467f85ba0100003188788c", specMAC, shellyKey, specMAC + " ctr=442 trigger", ErrDecrypt},
		{"no key", "450aeb84467f85ba0100003188788c", shellyMAC, "", shellyMAC + " ctr=0 trigger", ErrNoKey},
		{"key ignored for plaintext", "44000901552e3745c300", shellyMAC, shellyKey, shellyMAC + " trigger packet_id=9 battery=85% humidity=55% temperature=19.5°C", nil},

		// Shelly BLU plaintext, captured live.
		{"H&T", "44000901552e3745c300", "", "", "trigger packet_id=9 battery=85% humidity=55% temperature=19.5°C", nil},
		{"H&T outdoor, humidity over 100", "440058013d2e6f455b00", "", "", "trigger packet_id=88 battery=61% humidity=111% temperature=9.1°C", nil},
		{"Motion", "4400a1016405945c002101", "", "", "trigger packet_id=161 battery=100% illuminance=237lx motion=1", nil},
		{"Door/Window", "440060015c050000002d013f0c00", "", "", "trigger packet_id=96 battery=92% illuminance=0lx window=1 rotation=1.2°", nil},

		// Shelly BLU plaintext from Theengs, bthome-ble and yasp tests.
		{"Button1", "40001d01643a01", "", "", "packet_id=29 battery=100% button=1:press", nil},
		{"H&T negative, legacy hold", "4400ae01642e383afe45aaff", "", "", "trigger packet_id=174 battery=100% humidity=56% button=254:hold_press temperature=-8.6°C", nil},
		{"Wall Switch 4", "44001d01643a013a003a003a00", "", "", "trigger packet_id=29 battery=100% button=1:press button#1=0 button#2=0 button#3=0", nil},
		{"Wall Switch 4 legacy hold", "4400ab01643afe3a003a003a00", "", "", "trigger packet_id=171 battery=100% button=254:hold_press button#1=0 button#2=0 button#3=0", nil},
		{"Wall Switch 4 buttons 2 and 3", "403a003a013a03", "", "", "button=0 button#1=1:press button#2=3:triple_press", nil},
		{"Door/Window rotation", "44005d016405fc21002d013f9601", "", "", "trigger packet_id=93 battery=100% illuminance=87lx window=1 rotation=40.6°", nil},
		{"Door/Window closed", "44002b016405dc05002d003f0000", "", "", "trigger packet_id=43 battery=100% illuminance=15lx window=0 rotation=0°", nil},
		{"Motion lux", "4400020164059033002101", "", "", "trigger packet_id=2 battery=100% illuminance=132lx motion=1", nil},
		{"H&T Display ZB", "40002e01641e012e34451601", "", "", "packet_id=46 battery=100% light=1 humidity=52% temperature=27.8°C", nil},

		// Structure and errors.
		{"device info only", "40", "", "", "", nil},
		{"out of order", "4003bf1302ca09", "", "", "humidity=50.55% temperature=25.06°C", nil},
		{"unknown object mid-packet", "40015dfe5d0903b718", "", "", "battery=93%", ErrUnknownObject},
		{"truncated object", "40016402ca", "", "", "battery=100%", ErrTruncated},
		{"truncated text", "40530548656c", "", "", "", ErrTruncated},
		{"truncated command", "403b0203", "", "", "", ErrTruncated},
		{"truncated embedded MAC", "42b2188d", "", "", "", ErrTruncated},
		{"truncated encryption trailer", "41001122", shellyMAC, shellyKey, shellyMAC + " ctr=0", ErrTruncated},
		{"version 0", "00", "", "", "", ErrNotBTHome},
		{"empty", "", "", "", "", ErrNotBTHome},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data, mac, key := unhex(t, tc.data), parseMAC(t, tc.mac), []byte(nil)
			if tc.key != "" {
				key = unhex(t, tc.key)
			}
			p, err := Decode(data, mac, key)
			if !errors.Is(err, tc.err) || (tc.err == nil && err != nil) {
				t.Errorf("err = %v, want %v", err, tc.err)
			}
			if got := render(p); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
			for i := range data {
				Decode(data[:i], mac, key) // must not panic
			}
		})
	}

	_, err := Decode(unhex(t, "450aeb84467f85ba0100003188788c"), parseMAC(t, shellyMAC), make([]byte, 15))
	if err == nil || errors.Is(err, ErrNoKey) || errors.Is(err, ErrDecrypt) {
		t.Errorf("15-byte key: err = %v, want a key length error", err)
	}
}

func TestObjects(t *testing.T) {
	// One example per object ID, mostly from the bthome.io/format tables.
	tests := []struct{ data, want string }{
		{"0009", "packet_id=9"},
		{"0161", "battery=97%"},
		{"02CA09", "temperature=25.06°C"},
		{"03BF13", "humidity=50.55%"},
		{"04138A01", "pressure=1008.83hPa"},
		{"05138A14", "illuminance=13460.67lx"},
		{"065E1F", "mass=80.3kg"},
		{"073E1D", "mass=74.86lb"},
		{"08CA06", "dewpoint=17.38°C"},
		{"0960", "count=96"},
		{"0A138A14", "energy=1346.067kWh"},
		{"0B021B00", "power=69.14W"},
		{"0C020C", "voltage=3.074V"},
		{"0D120C", "pm25=3090µg/m³"},
		{"0E021C", "pm10=7170µg/m³"},
		{"0F01", "generic_boolean=1"},
		{"1001", "power_on=1"},
		{"1100", "opening=0"},
		{"12E204", "co2=1250ppm"},
		{"133301", "tvoc=307µg/m³"},
		{"14020C", "moisture=30.74%"},
		{"1501", "battery_low=1"},
		{"1601", "battery_charging=1"},
		{"1700", "carbon_monoxide=0"},
		{"1801", "cold=1"},
		{"1900", "connectivity=0"},
		{"1A00", "door=0"},
		{"1B01", "garage_door=1"},
		{"1C01", "gas_detected=1"},
		{"1D00", "heat=0"},
		{"1E01", "light=1"},
		{"1F01", "lock=1"},
		{"2001", "moisture_detected=1"},
		{"2100", "motion=0"},
		{"2201", "moving=1"},
		{"2301", "occupancy=1"},
		{"2400", "plug=0"},
		{"2500", "presence=0"},
		{"2601", "problem=1"},
		{"2701", "running=1"},
		{"2800", "safety=0"},
		{"2901", "smoke=1"},
		{"2A00", "sound=0"},
		{"2B00", "tamper=0"},
		{"2C01", "vibration=1"},
		{"2D01", "window=1"},
		{"2E23", "humidity=35%"},
		{"2F23", "moisture=35%"},
		{"3A003A013A023A033A043A053A063A803AFE3A07", "button=0 button#1=1:press button#2=2:double_press button#3=3:triple_press button#4=4:long_press button#5=5:long_double_press button#6=6:long_triple_press button#7=128:hold_press button#8=254:hold_press button#9=7"},
		{"3B00003B00013B00023B0103053B0104053B0005", "command=0:off command#1=1:on command#2=2:toggle command#3=3:step_up:05 command#4=4:step_down:05 command#5=5"},
		{"3C00003C01033C020A3C02C8", "dimmer=0:0000 dimmer#1=3:rotate_left:0103 dimmer#2=10:rotate_right:020a dimmer#3=200:rotate_right:02c8"},
		{"3D0960", "count=24585"},
		{"3E2A2C0960", "count=1611213866"},
		{"3F020C", "rotation=307.4°"},
		{"400C00", "distance=12mm"},
		{"414E00", "distance=7.8m"},
		{"424E3400", "duration=13.39s"},
		{"434E34", "current=13.39A"},
		{"444E34", "speed=133.9m/s"},
		{"451101", "temperature=27.3°C"},
		{"4632", "uv_index=5"},
		{"478756", "volume=2215.1L"},
		{"48DC87", "volume=34780mL"},
		{"49DC87", "volume_flow_rate=34.78m³/h"},
		{"4A020C", "voltage=307.4V"},
		{"4B138A14", "gas=1346.067m³"},
		{"4C41018A01", "gas=25821.505m³"},
		{"4D12138A14", "energy=344593.17kWh"},
		{"4E87562A01", "volume=19551.879L"},
		{"4F87562A01", "water=19551.879L"},
		{"505D396164", "timestamp=1684093277"},
		{"518756", "acceleration=22.151m/s²"},
		{"528756", "gyroscope=22.151°/s"},
		{"530C48656C6C6F20576F726C6421", "text=0:48656c6c6f20576f726c6421"},
		{"540C48656C6C6F20576F726C6421", "raw=0:48656c6c6f20576f726c6421"},
		{"5587562A01", "volume_storage=19551.879L"},
		{"56E803", "conductivity=1000µS/cm"},
		{"57EA", "temperature=-22°C"},
		{"58EA", "temperature=-7.7°C"},
		{"59EA", "count=-22"},
		{"5AEAEA", "count=-5398"},
		{"5BEA0234EA", "count=-365690134"},
		{"5C02FBFFFF", "power=-12.78W"},
		{"5D02EA", "current=-5.63A"},
		{"5E9F8C", "direction=359.99°"},
		{"5FA00F", "precipitation=400mm"},
		{"6001", "channel=1"},
		{"61AC0D", "rotational_speed=3500rpm"},
		{"624099DFFF", "speed=-2.123456m/s"},
		{"630057D0FF", "acceleration=-3.123456m/s²"},
		{"6402", "light_level=2"},
		{"6503", "settings_revision=3"},
		{"F00100", "device_type_id=1"},
		{"F100010204", "firmware_version=67240192"},
		{"F2000106", "firmware_version=393472"},
	}
	seen := map[byte]bool{}
	for _, tc := range tests {
		p, err := Decode(unhex(t, "40"+tc.data), MAC{}, nil)
		if err != nil {
			t.Errorf("%s: %v", tc.data, err)
		}
		if got := render(p); got != tc.want {
			t.Errorf("%s:\ngot  %s\nwant %s", tc.data, got, tc.want)
		}
		for _, o := range p.Objects {
			seen[o.ID] = true
		}
	}
	n := 0
	for id, ot := range objTypes {
		if ot.name != "" {
			n++
			if !seen[byte(id)] {
				t.Errorf("no example for object 0x%02X", id)
			}
		}
	}
	if n != 95 {
		t.Errorf("table has %d objects, want 95", n)
	}
}

// render formats a packet as "[MAC] [ctr=N] [trigger] name[#index]=value unit[:event][:raw]...",
// leaving out a zero MAC. Values print in shortest form, so inexact scaling shows.
func render(p Packet) string {
	var f []string
	if p.MAC != (MAC{}) {
		f = append(f, p.MAC.String())
	}
	if p.Encrypted {
		f = append(f, fmt.Sprintf("ctr=%d", p.Counter))
	}
	if p.Trigger {
		f = append(f, "trigger")
	}
	for _, o := range p.Objects {
		s := o.Name()
		if o.Index > 0 {
			s += fmt.Sprintf("#%d", o.Index)
		}
		s += "=" + strconv.FormatFloat(o.Value, 'f', -1, 64) + o.Unit()
		if e := o.Event(); e != "" {
			s += ":" + e
		}
		if o.Raw != nil {
			s += fmt.Sprintf(":%x", o.Raw)
		}
		f = append(f, s)
	}
	return strings.Join(f, " ")
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseMAC(t *testing.T, s string) MAC {
	t.Helper()
	var m MAC
	if s != "" && copy(m[:], unhex(t, strings.ReplaceAll(s, ":", ""))) != len(m) {
		t.Fatalf("bad MAC %q", s)
	}
	return m
}

func TestBinary(t *testing.T) {
	n := 0
	for id := range 256 {
		o := Object{ID: byte(id)}
		if !o.Binary() {
			continue
		}
		n++
		if typ := objTypes[id]; typ.name == "" || typ.unit != "" || typ.size != 1 {
			t.Errorf("0x%02X %q is not a binary sensor", id, typ.name)
		}
	}
	if n != 28 { // bthome.io lists 28 binary sensor objects
		t.Errorf("%d binary sensors, want 28", n)
	}
}
