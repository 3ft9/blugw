package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/3ft9/blugw/blugw"
	"github.com/3ft9/blugw/bthome"
)

func TestParseConfig(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	const (
		url = "tcp://broker:1883"
		key = testKey
	)
	tests := []struct {
		name string
		env  map[string]string
		want string // see render
		err  string // substring of the error, if one is expected
	}{
		{"defaults", map[string]string{}, "url=" + url + " user= name=" + host + " prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"all set", map[string]string{"BLUGW_MQTT_USER": "u", "BLUGW_MQTT_PASSWORD": "p", "BLUGW_NAME": "attic.local", "BLUGW_PREFIX": "home/ble", "BLUGW_WATCHDOG": "90s", "BLUGW_HA": "true", "BLUGW_HA_PREFIX": "ha", "BLUGW_LOG_LEVEL": "debug"},
			"url=" + url + " user=u name=attic.local prefix=home/ble keys=[] allow=all watchdog=1m30s ha=true haPrefix=ha level=DEBUG qos=1", ""},
		{"watchdog 0", map[string]string{"BLUGW_NAME": "gw", "BLUGW_WATCHDOG": "0"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=all watchdog=0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"keys", map[string]string{"BLUGW_NAME": "gw", "BLUGW_KEYS": " 38-39-8f-8c-77-da=" + key + ", ,B4:35:22:F5:3D:A4=" + strings.ToUpper(key) + ","},
			"url=" + url + " user= name=gw prefix=blugw keys=[38:39:8F:8C:77:DA=" + key + " B4:35:22:F5:3D:A4=" + key + "] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"include", map[string]string{"BLUGW_NAME": "gw", "BLUGW_INCLUDE": "38:39:8f:8c:77:da, 7c-c6-b6-73-ab-4e"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=+a+b-c watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"exclude", map[string]string{"BLUGW_NAME": "gw", "BLUGW_EXCLUDE": "B0:C7:DE:42:1F:D5"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=+a+b-c watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"include and exclude", map[string]string{"BLUGW_NAME": "gw", "BLUGW_INCLUDE": "38:39:8F:8C:77:DA,7C:C6:B6:73:AB:4E", "BLUGW_EXCLUDE": "7C:C6:B6:73:AB:4E"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=+a-b-c watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},

		{"TLS URL", map[string]string{"BLUGW_NAME": "gw", "BLUGW_MQTT_URL": "ssl://broker:8883"}, "url=ssl://broker:8883 user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"websocket URL", map[string]string{"BLUGW_NAME": "gw", "BLUGW_MQTT_URL": "wss://broker/mqtt"}, "url=wss://broker/mqtt user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},
		{"unix URL", map[string]string{"BLUGW_NAME": "gw", "BLUGW_MQTT_URL": "unix:///run/mosquitto.sock"}, "url=unix:///run/mosquitto.sock user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1", ""},

		{"no URL", map[string]string{"BLUGW_MQTT_URL": ""}, "", "BLUGW_MQTT_URL"},
		{"URL without scheme", map[string]string{"BLUGW_MQTT_URL": "broker:1883"}, "", "BLUGW_MQTT_URL"},
		{"URL without host", map[string]string{"BLUGW_MQTT_URL": "tcp://"}, "", "BLUGW_MQTT_URL"},
		{"URL without port", map[string]string{"BLUGW_MQTT_URL": "mqtt://bob:s3cret@broker"}, "", `BLUGW_MQTT_URL "mqtt://bob:xxxxx@broker"`},
		{"URL with bad port", map[string]string{"BLUGW_MQTT_URL": "tcp://broker:99999"}, "", "BLUGW_MQTT_URL"},
		{"URL with unknown scheme", map[string]string{"BLUGW_MQTT_URL": "http://broker:1883"}, "", "BLUGW_MQTT_URL"},
		{"URL not parsed", map[string]string{"BLUGW_MQTT_URL": "tcp://bob:s3cret@broker:1883/%zz"}, "", "BLUGW_MQTT_URL"},
		{"name with slash", map[string]string{"BLUGW_NAME": "a/b"}, "", "BLUGW_NAME"},
		{"name with plus", map[string]string{"BLUGW_NAME": "a+"}, "", "BLUGW_NAME"},
		{"name with hash", map[string]string{"BLUGW_NAME": "#"}, "", "BLUGW_NAME"},
		{"name not UTF-8", map[string]string{"BLUGW_NAME": "g\xffw"}, "", "BLUGW_NAME"},
		{"prefix with plus", map[string]string{"BLUGW_PREFIX": "a/+/b"}, "", "BLUGW_PREFIX"},
		{"prefix with hash", map[string]string{"BLUGW_PREFIX": "a/#"}, "", "BLUGW_PREFIX"},
		{"prefix with trailing slash", map[string]string{"BLUGW_PREFIX": "blugw/"}, "", "BLUGW_PREFIX"},
		{"prefix with leading slash", map[string]string{"BLUGW_PREFIX": "/blugw"}, "", "BLUGW_PREFIX"},
		{"prefix with empty level", map[string]string{"BLUGW_PREFIX": "a//b"}, "", "BLUGW_PREFIX"},
		{"prefix with dollar", map[string]string{"BLUGW_PREFIX": "$SYS"}, "", "BLUGW_PREFIX"},
		{"HA prefix with hash", map[string]string{"BLUGW_HA_PREFIX": "#"}, "", "BLUGW_HA_PREFIX"},
		{"HA prefix with trailing slash", map[string]string{"BLUGW_HA_PREFIX": "homeassistant/"}, "", "BLUGW_HA_PREFIX"},
		{"short key", map[string]string{"BLUGW_KEYS": "38:39:8F:8C:77:DA=" + key[2:]}, "", "BLUGW_KEYS: item 1"},
		{"key not hex", map[string]string{"BLUGW_KEYS": "38:39:8F:8C:77:DA=" + key[2:] + "zz"}, "", "BLUGW_KEYS"},
		{"key without MAC", map[string]string{"BLUGW_KEYS": key}, "", "BLUGW_KEYS"},
		{"key with bad MAC", map[string]string{"BLUGW_KEYS": "38:39:8F:8C:77:DA=" + key + ",38:39:8F:8C:77=" + key}, "", "BLUGW_KEYS: item 2"},
		{"key and MAC swapped", map[string]string{"BLUGW_KEYS": key + "=38:39:8F:8C:77:DA"}, "", "BLUGW_KEYS"},
		{"bad include", map[string]string{"BLUGW_INCLUDE": "38:39:8F:8C:77:DA,nope"}, "", `BLUGW_INCLUDE: "nope"`},
		{"8-byte MAC", map[string]string{"BLUGW_EXCLUDE": "01:02:03:04:05:06:07:08"}, "", "BLUGW_EXCLUDE"},
		{"bad watchdog", map[string]string{"BLUGW_WATCHDOG": "5"}, "", "BLUGW_WATCHDOG"},
		{"negative watchdog", map[string]string{"BLUGW_WATCHDOG": "-1m"}, "", "BLUGW_WATCHDOG"},
		{"bad HA", map[string]string{"BLUGW_HA": "yes"}, "", "BLUGW_HA"},
		{"QoS 0", map[string]string{"BLUGW_NAME": "gw", "BLUGW_MQTT_QOS": "0"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=0", ""},
		{"QoS 2", map[string]string{"BLUGW_NAME": "gw", "BLUGW_MQTT_QOS": "2"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=2", ""},
		{"bad QoS", map[string]string{"BLUGW_MQTT_QOS": "3"}, "", "BLUGW_MQTT_QOS"},
		{"QoS not a number", map[string]string{"BLUGW_MQTT_QOS": "one"}, "", "BLUGW_MQTT_QOS"},
		{"names", map[string]string{"BLUGW_NAME": "gw", "BLUGW_NAMES": " 38-39-8f-87-2b-3e = Office, upstairs ;; 7C:C6:B6:09:89:8F=Garden;"}, "url=" + url + " user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1 names=[\"38:39:8F:87:2B:3E=Office, upstairs\" \"7C:C6:B6:09:89:8F=Garden\"]", ""},
		{"name without MAC", map[string]string{"BLUGW_NAMES": "Office"}, "", `BLUGW_NAMES: "Office"`},
		{"name with bad MAC", map[string]string{"BLUGW_NAMES": "38:39:8F:87:2B=Office"}, "", "BLUGW_NAMES"},
		{"empty name", map[string]string{"BLUGW_NAMES": "38:39:8F:87:2B:3E= "}, "", "BLUGW_NAMES"},
		{"bad log level", map[string]string{"BLUGW_LOG_LEVEL": "loud"}, "", "BLUGW_LOG_LEVEL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseConfig(func(k string) string {
				if v, ok := tc.env[k]; ok {
					return v
				}
				if k == "BLUGW_MQTT_URL" {
					return url
				}
				return ""
			}, file{})
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				if leaks(err) {
					t.Errorf("error reveals a secret: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := render(c); got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
		})
	}
}

func TestConfigFile(t *testing.T) {
	const (
		key  = testKey
		full = `
mqtt:
  url: ssl://broker:8883
  user: blugw
  password: s3cret
  qos: 2
name: attic
prefix: home/ble
include: [38:39:8f:8c:77:da, 7C-C6-B6-73-AB-4E]
exclude:
  - 7C:C6:B6:73:AB:4E
names:
  38:39:8F:8C:77:DA: Office
keys:
  38:39:8F:8C:77:DA: ` + key + `
watchdog: 90s
homeassistant:
  enabled: true
  prefix: ha
log_level: debug
`
		want = "url=ssl://broker:8883 user=blugw name=attic prefix=home/ble keys=[38:39:8F:8C:77:DA=" + key + "] allow=+a-b-c watchdog=1m30s ha=true haPrefix=ha level=DEBUG qos=2 names=[\"38:39:8F:8C:77:DA=Office\"] password=s3cret"
		base = "mqtt: {url: tcp://broker:1883}\nname: gw\n"
		def  = "url=tcp://broker:1883 user= name=gw prefix=blugw keys=[] allow=all watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1"
	)
	// full as environment variables
	env := map[string]string{
		"BLUGW_MQTT_URL": "ssl://broker:8883", "BLUGW_MQTT_USER": "blugw", "BLUGW_MQTT_PASSWORD": "s3cret", "BLUGW_MQTT_QOS": "2",
		"BLUGW_NAME": "attic", "BLUGW_PREFIX": "home/ble", "BLUGW_INCLUDE": "38:39:8f:8c:77:da,7C-C6-B6-73-AB-4E", "BLUGW_EXCLUDE": "7C:C6:B6:73:AB:4E",
		"BLUGW_NAMES": "38:39:8F:8C:77:DA=Office", "BLUGW_KEYS": "38:39:8F:8C:77:DA=" + key,
		"BLUGW_WATCHDOG": "90s", "BLUGW_HA": "true", "BLUGW_HA_PREFIX": "ha", "BLUGW_LOG_LEVEL": "debug",
	}
	c, err := parseConfig(func(k string) string { return env[k] }, file{})
	if got := render(c) + " password=" + c.password; err != nil || got != want {
		t.Fatalf("environment: got %s, %v\nwant %s", got, err, want)
	}

	tests := []struct {
		name string
		yaml string
		env  map[string]string
		want string // render, then password=
		err  string // substring of the error, if one is expected
	}{
		{"full", full, nil, want, ""},
		{"environment overrides", full, map[string]string{"BLUGW_NAME": "gw", "BLUGW_PREFIX": "", "BLUGW_MQTT_PASSWORD": "env", "BLUGW_INCLUDE": "B0:C7:DE:42:1F:D5", "BLUGW_KEYS": "B4:35:22:F5:3D:A4=" + key, "BLUGW_HA": "false"},
			"url=ssl://broker:8883 user=blugw name=gw prefix=home/ble keys=[B4:35:22:F5:3D:A4=" + key + "] allow=-a-b+c watchdog=1m30s ha=false haPrefix=ha level=DEBUG qos=2 names=[\"38:39:8F:8C:77:DA=Office\"] password=env", ""},
		{"empty", "# nothing yet\n", map[string]string{"BLUGW_MQTT_URL": "tcp://broker:1883", "BLUGW_NAME": "gw"}, def + " password=", ""},
		{"names with separators", base + "names:\n  38:39:8F:87:2B:3E: Office; upstairs, left=1\n", nil, def + ` names=["38:39:8F:87:2B:3E=Office; upstairs, left=1"] password=`, ""},
		{"numbers stay text", base + "include: [11:22:33:44:55:66]\nnames: {11:22:33:44:55:66: 0012}\nkeys:\n  11:22:33:44:55:66: 12345678901234567890123456789012\n  00:11:22:33:44:55: 00000000000000000000000000000001\n  22:33:44:55:66:77: 1e345678901234567890123456789012\n",
			nil, "url=tcp://broker:1883 user= name=gw prefix=blugw keys=[00:11:22:33:44:55=00000000000000000000000000000001 11:22:33:44:55:66=12345678901234567890123456789012 22:33:44:55:66:77=1e345678901234567890123456789012] allow=-a-b-c watchdog=5m0s ha=false haPrefix=homeassistant level=INFO qos=1 names=[\"11:22:33:44:55:66=0012\"] password=", ""},

		{"yes is not true", base + "homeassistant: {enabled: yes}\n", nil, "", `blugw.yaml: homeassistant.enabled "yes": want true or false`},
		{"unknown key", "mqtt:\n  url: tcp://broker:1883\n  pasword: s3cret\n", nil, "", "line 3: field pasword not found"},
		{"unknown top-level key", base + "loglevel: debug\n", nil, "", "line 3: field loglevel not found"},
		{"no URL", "name: gw\n", nil, "", `blugw.yaml: mqtt.url "": want`},
		{"URL with password", "mqtt: {url: 'mqtt://bob:s3cret@broker'}\n", nil, "", `blugw.yaml: mqtt.url "mqtt://bob:xxxxx@broker"`},
		{"bad QoS", "mqtt: {url: tcp://broker:1883, qos: 3}\n", nil, "", `blugw.yaml: mqtt.qos "3"`},
		{"bad prefix", base + "prefix: a//b\n", nil, "", `blugw.yaml: prefix "a//b"`},
		{"bad MAC", base + "exclude: [nope]\n", nil, "", `blugw.yaml: exclude: "nope" is not a MAC address`},
		{"bad name", base + "names: {38:39:8F:87:2B: Office}\n", nil, "", `blugw.yaml: names: "38:39:8F:87:2B": want a MAC and a name`},
		{"short key", base + "keys: {38:39:8F:8C:77:DA: " + key[2:] + "}\n", nil, "", "blugw.yaml: keys: 38:39:8F:8C:77:DA: want"},
		{"key and MAC swapped", base + "keys: {" + key + ": 38:39:8F:8C:77:DA}\n", nil, "", "blugw.yaml: keys: an entry: want"},
		{"keys not a map", base + "keys: " + key + "\n", nil, "", "line 3: cannot unmarshal !!str into map[string]string"},
		{"mqtt not a map", "mqtt: s3cret\n", nil, "", "line 1: cannot unmarshal !!str into struct"},
		{"password as alias", "mqtt: {url: tcp://broker:1883, password: *s3cret}\n", nil, "", "yaml: unknown anchor referenced"},
		{"key as alias", base + "keys: {38:39:8F:8C:77:DA: *" + key + "}\n", nil, "", "yaml: unknown anchor referenced"},
		{"tagged password", "mqtt: {url: tcp://broker:1883, password: !!int s3cret}\n", nil, "", "yaml: cannot decode !!str as a !!int"},
		{"duplicate key", base + "keys:\n  " + key + ": a\n  " + key + ": b\n", nil, "", "line 5: mapping key already defined at line 4"},
		{"bad variable", full, map[string]string{"BLUGW_WATCHDOG": "5"}, "", `BLUGW_WATCHDOG "5"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "blugw.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := loadFile(path)
			var c config
			if err == nil {
				c, err = parseConfig(func(k string) string { return tc.env[k] }, f)
			}
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				if leaks(err) {
					t.Errorf("error reveals a secret: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := render(c) + " password=" + c.password; got != tc.want {
				t.Errorf("got  %s\nwant %s", got, tc.want)
			}
			if f.exposed {
				t.Error("exposed with mode 600")
			}
		})
	}
}

func TestConfigFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix file modes")
	}
	creds := t.TempDir()
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	tests := []struct {
		yaml string
		mode os.FileMode
		cred bool // in CREDENTIALS_DIRECTORY
		want bool // exposed
	}{
		{"mqtt: {password: s3cret}", 0o600, false, false},
		{"mqtt: {password: s3cret}", 0o640, false, true},
		{"keys: {38:39:8F:8C:77:DA: " + testKey + "}", 0o604, false, true},
		{"mqtt: {url: 'mqtt://bob:s3cret@broker:1883'}", 0o644, false, true},
		{"mqtt: {url: 'mqtt://bob@broker:1883', user: blugw}", 0o644, false, false},
		{"mqtt: {password: s3cret}", 0o440, true, false}, // systemd's ACL shows as group read
	}
	for _, tc := range tests {
		dir := t.TempDir()
		if tc.cred {
			dir = creds
		}
		path := filepath.Join(dir, "blugw.yaml")
		if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		if f, err := loadFile(path); err != nil || f.exposed != tc.want {
			t.Errorf("%s at %v: exposed = %v, %v; want %v", tc.yaml, tc.mode, f.exposed, err, tc.want)
		}
	}
}

const testKey = "90bffd73cb6b26ef58a7a8eba9232036"

// leaks reports whether err reveals the test password s3cret or any six
// digits in a row of testKey.
func leaks(err error) bool {
	e := strings.ToLower(err.Error())
	for i := range len(testKey) - 5 {
		if strings.Contains(e, testKey[i:i+6]) {
			return true
		}
	}
	return strings.Contains(e, "s3cret")
}

// render summarises c. allow shows, for MACs a, b and c, + if allowed and -
// if not, or "all" when Allow is nil.
func render(c config) string {
	var keys []string
	for m, k := range c.opts.Keys {
		keys = append(keys, m.String()+"="+hex.EncodeToString(k))
	}
	slices.Sort(keys)
	allow := "all"
	if c.opts.Allow != nil {
		allow = ""
		for i, m := range []string{"38:39:8F:8C:77:DA", "7C:C6:B6:73:AB:4E", "B0:C7:DE:42:1F:D5"} {
			mac, _ := parseMAC(m)
			sign := "-"
			if c.opts.Allow(mac) {
				sign = "+"
			}
			allow += sign + string(rune('a'+i))
		}
	}
	out := fmt.Sprintf("url=%s user=%s name=%s prefix=%s keys=%v allow=%s watchdog=%s ha=%v haPrefix=%s level=%s qos=%d",
		c.url, c.user, c.name, c.prefix, keys, allow, c.opts.Watchdog, c.ha, c.haPrefix, c.level, c.qos)
	if len(c.names) > 0 {
		var names []string
		for m, n := range c.names {
			names = append(names, m.String()+"="+n)
		}
		slices.Sort(names)
		out += fmt.Sprintf(" names=%q", names)
	}
	return out
}

var testMAC = bthome.MAC{0x38, 0x39, 0x8F, 0x8C, 0x77, 0xDA}

// reading decodes BTHome service data from testMAC, received at 17:57:14.348 UTC.
func reading(t *testing.T, data string, model uint16, name string) blugw.Reading {
	t.Helper()
	b, err := hex.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	p, err := bthome.Decode(b, testMAC, nil)
	if err != nil {
		t.Fatal(err)
	}
	return blugw.Reading{Packet: p, Model: model, Name: name, RSSI: -68, Time: time.Date(2026, 10, 23, 18, 57, 14, 348e6, time.FixedZone("BST", 3600))}
}

// show renders messages as "topic [retained] [delayed] payload".
func show(msgs []message) []string {
	var s []string
	for _, m := range msgs {
		r := ""
		if m.retain {
			r = "retained "
		}
		if m.delay {
			r += "delayed "
		}
		s = append(s, m.topic+" "+r+string(m.payload))
	}
	return s
}

// TestMessages runs with Home Assistant discovery off, so wants are exact.
func TestMessages(t *testing.T) {
	const state = "blugw/device/38398f8c77da retained "
	type step struct {
		r    blugw.Reading
		want []string
	}
	tests := []struct {
		name  string
		steps []step
	}{
		{"H&T", []step{
			{reading(t, "44000901552e3745c300", 3, "SBHT-003C"), []string{
				state + `{"battery":85,"encrypted":false,"gateway":"test","humidity":55,"local_name":"SBHT-003C","mac":"38:39:8F:8C:77:DA","model_id":3,"packet_id":9,"rssi":-68,"temperature":19.5,"time":"2026-10-23T17:57:14.348Z"}`,
			}},
		}},
		{"device info merges", []step{
			{reading(t, "44000901552e3745c300", 0, ""), []string{
				state + `{"battery":85,"encrypted":false,"gateway":"test","humidity":55,"mac":"38:39:8F:8C:77:DA","packet_id":9,"rssi":-68,"temperature":19.5,"time":"2026-10-23T17:57:14.348Z"}`,
			}},
			{reading(t, "4400de0164f00300f100170001", 3, ""), []string{
				state + `{"battery":100,"encrypted":false,"firmware":"1.0.23.0","gateway":"test","humidity":55,"mac":"38:39:8F:8C:77:DA","model_id":3,"packet_id":222,"rssi":-68,"temperature":19.5,"time":"2026-10-23T17:57:14.348Z"}`,
			}},
		}},
		{"Wall Switch 4", []step{
			{reading(t, "44001d01643a013a003a003a00", 6, ""), []string{
				state + `{"battery":100,"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","model_id":6,"packet_id":29,"rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`,
				`blugw/device/38398f8c77da/event/button {"event_type":"press"}`,
			}},
			{reading(t, "44001e01643a003a003a013a00", 6, ""), []string{
				state + `{"battery":100,"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","model_id":6,"packet_id":30,"rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`,
				`blugw/device/38398f8c77da/event/button_3 {"event_type":"press"}`,
			}},
		}},
		{"Door/Window", []step{
			{reading(t, "440060015c050000002d013f0c00", 0, ""), []string{
				state + `{"battery":92,"encrypted":false,"gateway":"test","illuminance":0,"mac":"38:39:8F:8C:77:DA","packet_id":96,"rotation":1.2,"rssi":-68,"time":"2026-10-23T17:57:14.348Z","window":true}`,
			}},
			{reading(t, "440063015c050000002d003f0000", 0, ""), []string{
				state + `{"battery":92,"encrypted":false,"gateway":"test","illuminance":0,"mac":"38:39:8F:8C:77:DA","packet_id":99,"rotation":0,"rssi":-68,"time":"2026-10-23T17:57:14.348Z","window":false}`,
			}},
		}},
		{"dimmer and command", []step{
			{reading(t, "403c0103", 0, ""), []string{
				state + `{"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`,
				`blugw/device/38398f8c77da/event/dimmer {"event_type":"rotate_left","steps":3}`,
			}},
			{reading(t, "403c0000", 0, ""), []string{
				state + `{"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`,
			}},
			{reading(t, "403b010305", 0, ""), []string{
				state + `{"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`,
				`blugw/device/38398f8c77da/event/command {"args":"05","event_type":"step_up"}`,
			}},
		}},
		{"text and raw", []step{
			{reading(t, "4053024869540201ff", 0, ""), []string{
				state + `{"encrypted":false,"gateway":"test","mac":"38:39:8F:8C:77:DA","raw":"01ff","rssi":-68,"text":"Hi","time":"2026-10-23T17:57:14.348Z"}`,
			}},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateway(config{name: "test", prefix: "blugw"})
			for i, s := range tc.steps {
				got, want := show(g.messages(s.r)), s.want
				if !slices.Equal(got, want) {
					t.Errorf("step %d:\ngot  %q\nwant %q", i, got, want)
				}
			}
		})
	}
}

const htConfig = `{"availability_topic":"blugw/gateway/test/status","components":{` +
	`"38398f8c77da_battery":{"device_class":"battery","name":"Battery","platform":"sensor","state_class":"measurement","unique_id":"blugw_38398f8c77da_battery","unit_of_measurement":"%","value_template":"{% if value_json.battery is defined %}{{ value_json.battery }}{% endif %}"},` +
	`"38398f8c77da_humidity":{"device_class":"humidity","name":"Humidity","platform":"sensor","state_class":"measurement","unique_id":"blugw_38398f8c77da_humidity","unit_of_measurement":"%","value_template":"{% if value_json.humidity is defined %}{{ value_json.humidity }}{% endif %}"},` +
	`"38398f8c77da_packet_id":{"entity_category":"diagnostic","name":"Packet Id","platform":"sensor","unique_id":"blugw_38398f8c77da_packet_id","value_template":"{% if value_json.packet_id is defined %}{{ value_json.packet_id }}{% endif %}"},` +
	`"38398f8c77da_rssi":{"device_class":"signal_strength","entity_category":"diagnostic","name":"Rssi","platform":"sensor","state_class":"measurement","unique_id":"blugw_38398f8c77da_rssi","unit_of_measurement":"dBm","value_template":"{{ value_json.rssi }}"},` +
	`"38398f8c77da_temperature":{"device_class":"temperature","name":"Temperature","platform":"sensor","state_class":"measurement","unique_id":"blugw_38398f8c77da_temperature","unit_of_measurement":"°C","value_template":"{% if value_json.temperature is defined %}{{ value_json.temperature }}{% endif %}"}},` +
	`"device":{"connections":[["bluetooth","38:39:8f:8c:77:da"]],"identifiers":["blugw_38398f8c77da"],"manufacturer":"Shelly","model":"BLU H&T","model_id":"SBHT-003C","name":"BLU H&T 77DA"},` +
	`"origin":{"name":"blugw-mqtt","support_url":"https://github.com/3ft9/blugw"},"qos":1,"state_topic":"blugw/device/38398f8c77da"}`

func TestDiscovery(t *testing.T) {
	const (
		disc  = "homeassistant/device/blugw_38398f8c77da/config"
		state = "blugw/device/38398f8c77da"
	)
	g := newGateway(config{name: "test", prefix: "blugw", ha: true, haPrefix: "homeassistant", qos: 1})
	steps := []struct {
		name      string
		r         blugw.Reading
		reconnect bool     // bump the connection generation first
		topics    []string // published, in order, " delayed" marking delayed events
		config    string   // discovery payload, or a substring of it
	}{
		{"first seen", reading(t, "44000901552e3745c300", 3, "SBHT-003C"), false, []string{disc, state}, htConfig},
		{"same components", reading(t, "44000a01552e3745c300", 3, "SBHT-003C"), false, []string{state}, ""},
		{"reconnect", reading(t, "44000b01592e3745c300", 3, "SBHT-003C"), true, []string{disc, state}, htConfig},
		{"firmware", reading(t, "44000c0164f00300f100170001", 3, "SBHT-003C"), false, []string{disc, state}, `"sw_version":"1.0.23.0"`},
		{"button before its event", reading(t, "4400ae01642e383afe45aaff", 3, "SBHT-003C"), false, []string{disc, state, state + "/event/button delayed"},
			`"38398f8c77da_button":{"device_class":"button","event_types":["press","double_press","triple_press","long_press","long_double_press","long_triple_press","hold_press"],"name":"Button","platform":"event","state_topic":"blugw/device/38398f8c77da/event/button","unique_id":"blugw_38398f8c77da_button"}`},
		{"button again", reading(t, "4400af01643a01", 3, "SBHT-003C"), false, []string{state, state + "/event/button"}, ""},
		{"safety inverted", reading(t, "402801", 3, "SBHT-003C"), false, []string{disc, state},
			`"38398f8c77da_safety":{"device_class":"safety","name":"Safety","platform":"binary_sensor","unique_id":"blugw_38398f8c77da_safety","value_template":"{% if value_json.safety is defined %}{{ 'OFF' if value_json.safety else 'ON' }}{% endif %}"}`},
		{"binary classes", reading(t, "40150120011c010f01", 3, "SBHT-003C"), false, []string{disc, state},
			`"38398f8c77da_gas_detected":{"device_class":"gas","name":"Gas Detected","platform":"binary_sensor","unique_id":"blugw_38398f8c77da_gas_detected","value_template":"{% if value_json.gas_detected is defined %}{{ 'ON' if value_json.gas_detected else 'OFF' }}{% endif %}"},` +
				`"38398f8c77da_generic_boolean":{"name":"Generic Boolean","platform":"binary_sensor","unique_id":"blugw_38398f8c77da_generic_boolean","value_template":"{% if value_json.generic_boolean is defined %}{{ 'ON' if value_json.generic_boolean else 'OFF' }}{% endif %}"}`},
		{"repeated names and units", reading(t, "40456400454c0047e803480001", 3, "SBHT-003C"), false, []string{disc, state},
			`"38398f8c77da_temperature_2":{"device_class":"temperature","name":"Temperature 2","platform":"sensor","state_class":"measurement","unique_id":"blugw_38398f8c77da_temperature_2","unit_of_measurement":"°C","value_template":"{% if value_json.temperature_2 is defined %}{{ value_json.temperature_2 }}{% endif %}"},` +
				`"38398f8c77da_volume":{"device_class":"volume","name":"Volume","platform":"sensor","state_class":"total","unique_id":"blugw_38398f8c77da_volume","unit_of_measurement":"L","value_template":"{% if value_json.volume is defined %}{{ value_json.volume }}{% endif %}"},` +
				`"38398f8c77da_volume_2":{"device_class":"volume","name":"Volume 2","platform":"sensor","state_class":"total","unique_id":"blugw_38398f8c77da_volume_2","unit_of_measurement":"mL","value_template":"{% if value_json.volume_2 is defined %}{{ value_json.volume_2 }}{% endif %}"}`},
	}
	for _, s := range steps {
		if s.reconnect {
			g.conn.Add(1)
		}
		msgs := g.messages(s.r)
		var topics []string
		for _, m := range msgs {
			if m.delay {
				topics = append(topics, m.topic+" delayed")
			} else {
				topics = append(topics, m.topic)
			}
			if m.retain != !strings.Contains(m.topic, "/event/") {
				t.Errorf("%s: %s retain = %v", s.name, m.topic, m.retain)
			}
		}
		if !slices.Equal(topics, s.topics) {
			t.Errorf("%s: topics %q, want %q", s.name, topics, s.topics)
			continue
		}
		switch got := string(msgs[0].payload); {
		case s.config == "":
		case strings.HasPrefix(s.config, "{"):
			if got != s.config {
				t.Errorf("%s: config\ngot  %s\nwant %s", s.name, got, s.config)
			}
		case !strings.Contains(got, s.config):
			t.Errorf("%s: config\n%s\ndoes not contain\n%s", s.name, got, s.config)
		}
	}
}

func TestNames(t *testing.T) {
	g := newGateway(config{name: "test", prefix: "blugw", ha: true, haPrefix: "homeassistant", qos: 1, names: map[bthome.MAC]string{testMAC: "Office"}})
	msgs := g.messages(reading(t, "44000901552e3745c300", 3, "SBHT-003C"))
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want config and state", len(msgs))
	}
	if cfg := string(msgs[0].payload); !strings.Contains(cfg, `"name":"Office"}`) {
		t.Errorf("device name not set in config: %s", cfg)
	}
	if state := string(msgs[1].payload); !strings.Contains(state, `"local_name":"SBHT-003C","mac":"38:39:8F:8C:77:DA","model_id":3,"name":"Office"`) {
		t.Errorf("name not in state: %s", state)
	}
}

func TestRestore(t *testing.T) {
	const (
		state = "blugw/device/38398f8c77da"
		disc  = "homeassistant/device/blugw_38398f8c77da/config"
		// Published before a restart, with an older battery, rssi and time,
		// and a name from a BLUGW_NAMES entry removed since.
		old = `{"battery":85,"encrypted":false,"gateway":"test","humidity":55,"local_name":"SBHT-003C","mac":"38:39:8F:8C:77:DA","model_id":3,"name":"Office","packet_id":9,"rssi":-80,"temperature":19.5,"time":"2026-10-23T11:00:00.000Z"}`
		// After a device-info packet, without and with the old state.
		info   = `{"battery":100,"encrypted":false,"firmware":"1.0.23.0","gateway":"test","mac":"38:39:8F:8C:77:DA","model_id":3,"packet_id":222,"rssi":-68,"time":"2026-10-23T17:57:14.348Z"}`
		merged = `{"battery":100,"encrypted":false,"firmware":"1.0.23.0","gateway":"test","humidity":55,"local_name":"SBHT-003C","mac":"38:39:8F:8C:77:DA","model_id":3,"packet_id":222,"rssi":-68,"temperature":19.5,"time":"2026-10-23T17:57:14.348Z"}`
		button = `"38398f8c77da_button":{"device_class":"button","event_types":["press"],"name":"Button","platform":"event","state_topic":"blugw/device/38398f8c77da/event/button","unique_id":"blugw_38398f8c77da_button"}`
	)
	cfg := strings.Replace(htConfig, `"components":{`, `"components":{`+button+",", 1)
	tests := []struct {
		name           string
		topic, payload string
		deny           bool   // BLUGW_EXCLUDE has the device
		state          string // published after a device-info packet
		button         bool   // whether the config keeps the restored button
	}{
		{"state", state, old, false, merged, false},
		{"config", disc, cfg, false, info, true},
		{"foreign gateway", state, strings.Replace(old, `"gateway":"test"`, `"gateway":"attic"`, 1), false, info, false},
		{"other origin", disc, strings.Replace(cfg, `"name":"blugw-mqtt"`, `"name":"zigbee2mqtt"`, 1), false, info, false},
		{"other identifiers", disc, strings.Replace(cfg, `"identifiers":["blugw_38398f8c77da"]`, `"identifiers":["0x38398f8c77da"]`, 1), false, info, false},
		{"state not allowed", state, old, true, info, false},
		{"config not allowed", disc, cfg, true, info, false},
		{"malformed state", state, old[:40], false, info, false},
		{"state not an object", state, `["gateway","test"]`, false, info, false},
		{"malformed config", disc, cfg[:40], false, info, false},
		{"component not an object", disc, strings.Replace(cfg, `"components":{`, `"components":{"x":1,`, 1), false, info, false},
		{"config on state topic", state, cfg, false, info, false},
		{"state on config topic", disc, old, false, info, false},
		{"upper-case topic", "blugw/device/38398F8C77DA", old, false, info, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := newGateway(config{name: "test", prefix: "blugw", ha: true, haPrefix: "homeassistant", qos: 1})
			g.opts.Allow = func(bthome.MAC) bool { return !tc.deny }
			g.restore(tc.topic, []byte(tc.payload))
			msgs := g.messages(reading(t, "4400de0164f00300f100170001", 3, ""))
			if len(msgs) != 2 {
				t.Fatalf("got %q, want config and state", show(msgs))
			}
			if got := string(msgs[1].payload); got != tc.state {
				t.Errorf("state\ngot  %s\nwant %s", got, tc.state)
			}
			if got := strings.Contains(string(msgs[0].payload), button); got != tc.button {
				t.Errorf("config has the restored button: %v, want %v", got, tc.button)
			}
		})
	}
}
