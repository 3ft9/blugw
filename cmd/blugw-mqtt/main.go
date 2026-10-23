// Command blugw-mqtt publishes BTHome v2 readings from Shelly BLU and other
// Bluetooth LE sensors to MQTT, optionally with Home Assistant discovery.
//
// It is configured with environment variables and, optionally, a YAML file;
// run it with -h for the list.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/3ft9/blugw/blugw"
	"github.com/3ft9/blugw/bthome"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"go.yaml.in/yaml/v3"
)

const usage = `Usage: blugw-mqtt [-config file]

Scans Bluetooth LE for BTHome v2 devices, such as Shelly BLU sensors, and
publishes their readings to MQTT. It is configured with environment variables:

  BLUGW_MQTT_URL       broker URL, e.g. tcp://host:1883, ssl://host:8883 or
                       ws://host:8080/mqtt (required)
  BLUGW_MQTT_USER      broker user name
  BLUGW_MQTT_PASSWORD  broker password
  BLUGW_MQTT_QOS       MQTT QoS for every message: 0, 1 or 2 (default: 1)
  BLUGW_NAME           gateway name (default: host name)
  BLUGW_PREFIX         topic prefix (default: blugw)
  BLUGW_INCLUDE        comma-separated MACs; if set, only these devices are
                       published
  BLUGW_EXCLUDE        comma-separated MACs that are never published
  BLUGW_NAMES          semicolon-separated MAC=name pairs naming devices, e.g.
                       38:39:8F:87:2B:3E=Office;7C:C6:B6:09:89:8F=Garden
  BLUGW_KEYS           comma-separated MAC=key pairs for encrypted devices;
                       each key is 32 hex digits
  BLUGW_WATCHDOG       restart scanning when no BTHome advert has arrived for
                       this long; 0 disables (default: 5m)
  BLUGW_HA             publish Home Assistant MQTT discovery: true or false
                       (default: false)
  BLUGW_HA_PREFIX      Home Assistant discovery prefix (default: homeassistant)
  BLUGW_LOG_LEVEL      debug, info, warn or error (default: info)

-config reads the same settings from a YAML file, with the keys mqtt.url,
mqtt.user, mqtt.password, mqtt.qos, name, prefix, include, exclude, names,
keys, watchdog, homeassistant.enabled, homeassistant.prefix and log_level.
include and exclude are lists of MACs; names and keys map MACs to values. A
variable that is set and not empty overrides the file's value.

Topics, with <mac> as 12 lower-case hex digits:

  <prefix>/gateway/<name>/status   online or offline (retained)
  <prefix>/device/<mac>            last known device state as JSON (retained)
  <prefix>/device/<mac>/event/<key>
                                   button, dimmer and command events as JSON
`

func main() {
	path := flag.String("config", "", "")
	flag.Usage = func() { fmt.Fprint(flag.CommandLine.Output(), usage) }
	flag.Parse()
	if flag.NArg() > 0 || *path == "" && os.Getenv("BLUGW_MQTT_URL") == "" {
		flag.Usage()
		os.Exit(2)
	}
	var f file
	if *path != "" {
		var err error
		if f, err = loadFile(*path); err != nil {
			fmt.Fprintln(os.Stderr, "blugw-mqtt:", err)
			os.Exit(2)
		}
	}
	cfg, err := parseConfig(os.Getenv, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "blugw-mqtt:", err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.level})))
	if f.exposed {
		slog.Warn("blugw-mqtt: the config file holds secrets but group or others can read it", "file", f.path)
	}

	g := newGateway(cfg)
	c := connect(g)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(ctx, stop) // a second signal kills a hung shutdown
	code := 0
	err = blugw.Scan(ctx, cfg.opts, func(r blugw.Reading) { publish(c, g.qos, g.messages(r)) })
	if ctx.Err() == nil {
		slog.Error("blugw-mqtt: scanning failed", "err", err)
		code = 1
	}
	g.mu.Lock()
	g.stopping = true
	g.mu.Unlock()
	// Without a clean disconnect the broker publishes the will, "offline".
	if t := c.Publish(g.status(), g.qos, true, "offline"); t.WaitTimeout(2*time.Second) && t.Error() == nil {
		c.Disconnect(250)
	}
	os.Exit(code)
}

// connect returns a client that connects to the broker in the background,
// retrying until it succeeds, and reconnects whenever the connection drops.
func connect(g *gateway) mqtt.Client {
	c := mqtt.NewClient(mqtt.NewClientOptions().
		AddBroker(g.url).
		SetClientID("blugw-"+g.name).
		SetUsername(g.user).
		SetPassword(g.password).
		SetCleanSession(true).
		SetKeepAlive(30*time.Second).
		SetWriteTimeout(5*time.Second). // keepalive pings queue behind a stalled write
		SetStore(mqtt.NewOrderedMemoryStore()).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(10*time.Second).
		SetMaxReconnectInterval(time.Minute).
		SetWill(g.status(), "offline", g.qos, true).
		SetOnConnectHandler(func(c mqtt.Client) {
			g.conn.Add(1)
			g.mu.Lock()
			defer g.mu.Unlock()
			if !g.stopping {
				c.Publish(g.status(), g.qos, true, "online")
			}
		}).
		SetConnectionNotificationHandler(func(_ mqtt.Client, n mqtt.ConnectionNotification) {
			switch n := n.(type) {
			case mqtt.ConnectionNotificationConnected:
				slog.Info("mqtt: connected")
			case mqtt.ConnectionNotificationLost:
				slog.Warn("mqtt: connection lost, reconnecting", "err", n.Reason)
			case mqtt.ConnectionNotificationFailed:
				slog.Warn("mqtt: cannot connect, retrying", "err", n.Reason)
			}
		}))
	c.Connect()
	return c
}

// publish sends msgs without waiting for acknowledgements. While
// disconnected it drops them rather than queueing, as state is retained and
// republished with the next reading. At QoS 1 and 2, messages sent but
// unacknowledged when a connection drops are resent, in order, after
// reconnecting, so events sent before keepalive notices a dead connection
// arrive late; QoS 0 loses them instead.
func publish(c mqtt.Client, qos byte, msgs []message) {
	for _, m := range msgs {
		if m.delay {
			m.delay = false
			time.AfterFunc(2*time.Second, func() { publish(c, qos, []message{m}) })
			continue
		}
		slog.Debug("publish", "topic", m.topic, "retain", m.retain, "payload", string(m.payload))
		if c.IsConnectionOpen() {
			c.Publish(m.topic, qos, m.retain, m.payload)
		}
	}
}

type config struct {
	url, user, password string
	name, prefix        string
	opts                blugw.Options
	ha                  bool
	haPrefix            string
	level               slog.Level
	qos                 byte
	names               map[bthome.MAC]string
}

// file is the -config YAML file. Its keys are the lower-cased field names.
// Every scalar is a string, which YAML fills with the text as written, so
// MACs, keys with leading zeros and "yes" reach the same validation as the
// environment variables do.
type file struct {
	MQTT             struct{ URL, User, Password, QoS string }
	Name, Prefix     string
	Include, Exclude []string
	Names, Keys      map[string]string
	Watchdog         string
	HomeAssistant    struct{ Enabled, Prefix string }
	LogLevel         string `yaml:"log_level"`

	path    string // where the file was read from; empty if there is none
	exposed bool   // holds secrets, but group or others can read it
}

// loadFile reads the configuration file at path, rejecting unknown keys.
func loadFile(path string) (file, error) {
	f := file{path: path}
	r, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer r.Close()
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil && err != io.EOF {
		// A type error quotes the start of the value, which may be a secret.
		var te *yaml.TypeError
		if errors.As(err, &te) {
			for i, e := range te.Errors {
				if a, b := strings.Index(e, " `"), strings.LastIndex(e, "` "); a >= 0 && b > a {
					te.Errors[i] = e[:a] + e[b+1:]
				}
			}
		}
		return f, fmt.Errorf("%s: %w", path, err)
	}
	if fi, err := r.Stat(); err == nil && runtime.GOOS != "windows" {
		f.exposed = fi.Mode().Perm()&0o077 != 0 && (f.MQTT.Password != "" || len(f.Keys) > 0)
	}
	return f, nil
}

// parseConfig reads the configuration from getenv and f. A variable that is
// not empty overrides the file's value for the same setting.
func parseConfig(getenv func(string) string, f file) (config, error) {
	// label names a setting in errors: env, unless the value came from f.
	label := func(env, key string) string {
		if f.path == "" || getenv(env) != "" {
			return env
		}
		return f.path + ": " + key
	}
	c := config{
		url:      cmp.Or(getenv("BLUGW_MQTT_URL"), f.MQTT.URL),
		user:     cmp.Or(getenv("BLUGW_MQTT_USER"), f.MQTT.User),
		password: cmp.Or(getenv("BLUGW_MQTT_PASSWORD"), f.MQTT.Password),
		name:     cmp.Or(getenv("BLUGW_NAME"), f.Name),
		prefix:   cmp.Or(getenv("BLUGW_PREFIX"), f.Prefix, "blugw"),
		haPrefix: cmp.Or(getenv("BLUGW_HA_PREFIX"), f.HomeAssistant.Prefix, "homeassistant"),
		qos:      1,
		opts:     blugw.Options{Watchdog: 5 * time.Minute},
	}
	const wantURL = "want e.g. tcp://host:1883, ssl://host:8883 or ws://host:8080/mqtt"
	u, err := url.Parse(c.url)
	if err != nil {
		// Not wrapped: the error holds the URL, password and all.
		return c, errors.New(label("BLUGW_MQTT_URL", "mqtt.url") + ": " + wantURL)
	}
	ok := false
	switch u.Scheme { // those paho supports
	case "tcp", "mqtt", "ssl", "tls", "mqtts", "mqtt+ssl", "tcps":
		port, err := strconv.ParseUint(u.Port(), 10, 16)
		ok = u.Hostname() != "" && err == nil && port > 0
	case "ws", "wss":
		ok = u.Hostname() != ""
	case "unix":
		ok = u.Host != "" || u.Path != ""
	}
	if !ok {
		return c, fmt.Errorf("%s %q: %s", label("BLUGW_MQTT_URL", "mqtt.url"), u.Redacted(), wantURL)
	}
	if c.name == "" {
		h, err := os.Hostname()
		if err != nil {
			return c, fmt.Errorf("%s is not set and the host name is unknown: %w", label("BLUGW_NAME", "name"), err)
		}
		c.name = h
	}
	if !topicLevels(c.name) || strings.Contains(c.name, "/") {
		return c, fmt.Errorf("%s %q: want one MQTT topic level, without / + #", label("BLUGW_NAME", "name"), c.name)
	}
	if !topicLevels(c.prefix) || strings.HasPrefix(c.prefix, "$") {
		return c, fmt.Errorf("%s %q: want topic levels such as blugw or home/ble, without + #, empty levels or a leading $", label("BLUGW_PREFIX", "prefix"), c.prefix)
	}
	if !topicLevels(c.haPrefix) || strings.HasPrefix(c.haPrefix, "$") {
		return c, fmt.Errorf("%s %q: want topic levels such as homeassistant, without + #, empty levels or a leading $", label("BLUGW_HA_PREFIX", "homeassistant.prefix"), c.haPrefix)
	}

	include, err := macSet(label("BLUGW_INCLUDE", "include"), getenv("BLUGW_INCLUDE"), f.Include)
	if err != nil {
		return c, err
	}
	exclude, err := macSet(label("BLUGW_EXCLUDE", "exclude"), getenv("BLUGW_EXCLUDE"), f.Exclude)
	if err != nil {
		return c, err
	}
	if len(include) > 0 || len(exclude) > 0 {
		c.opts.Allow = func(m bthome.MAC) bool {
			return (len(include) == 0 || include[m]) && !exclude[m]
		}
	}

	addName := func(ms, name string) bool {
		mac, err := parseMAC(strings.TrimSpace(ms))
		if name = strings.TrimSpace(name); err != nil || name == "" {
			return false
		}
		if c.names == nil {
			c.names = map[bthome.MAC]string{}
		}
		c.names[mac] = name
		return true
	}
	if s := getenv("BLUGW_NAMES"); s != "" {
		for item := range strings.SplitSeq(s, ";") {
			if item = strings.TrimSpace(item); item == "" {
				continue
			}
			if ms, name, _ := strings.Cut(item, "="); !addName(ms, name) {
				return c, fmt.Errorf("BLUGW_NAMES: %q: want MAC=name", item)
			}
		}
	} else {
		for ms, name := range f.Names {
			if !addName(ms, name) {
				return c, fmt.Errorf("%s: names: %q: want a MAC and a name", f.path, ms)
			}
		}
	}

	addKey := func(ms, ks string) bool {
		mac, err := parseMAC(ms)
		key, kerr := hex.DecodeString(ks)
		if err != nil || kerr != nil || len(key) != 16 {
			return false
		}
		if c.opts.Keys == nil {
			c.opts.Keys = map[bthome.MAC][]byte{}
		}
		c.opts.Keys[mac] = key
		return true
	}
	// Keys are secret, and a malformed item may be all key, so errors quote
	// neither.
	if s := getenv("BLUGW_KEYS"); s != "" {
		for i, item := range list(s) {
			if ms, ks, _ := strings.Cut(item, "="); !addKey(ms, ks) {
				return c, fmt.Errorf("BLUGW_KEYS: item %d: want MAC=<32 hex digits>", i+1)
			}
		}
	} else {
		for ms, ks := range f.Keys {
			if !addKey(ms, ks) {
				entry := "an entry"
				if mac, err := parseMAC(ms); err == nil {
					entry = mac.String()
				}
				return c, fmt.Errorf("%s: keys: %s: want a MAC and 32 hex digits", f.path, entry)
			}
		}
	}

	if s := cmp.Or(getenv("BLUGW_WATCHDOG"), f.Watchdog); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return c, fmt.Errorf("%s %q: want a duration such as 5m, or 0 to disable", label("BLUGW_WATCHDOG", "watchdog"), s)
		}
		c.opts.Watchdog = d
	}
	if s := cmp.Or(getenv("BLUGW_HA"), f.HomeAssistant.Enabled); s != "" {
		if c.ha, err = strconv.ParseBool(s); err != nil {
			return c, fmt.Errorf("%s %q: want true or false", label("BLUGW_HA", "homeassistant.enabled"), s)
		}
	}
	if s := cmp.Or(getenv("BLUGW_MQTT_QOS"), f.MQTT.QoS); s != "" {
		q, err := strconv.ParseUint(s, 10, 8)
		if err != nil || q > 2 {
			return c, fmt.Errorf("%s %q: want 0, 1 or 2", label("BLUGW_MQTT_QOS", "mqtt.qos"), s)
		}
		c.qos = byte(q)
	}
	if s := cmp.Or(getenv("BLUGW_LOG_LEVEL"), f.LogLevel); s != "" {
		if err := c.level.UnmarshalText([]byte(s)); err != nil {
			return c, fmt.Errorf("%s %q: want debug, info, warn or error", label("BLUGW_LOG_LEVEL", "log_level"), s)
		}
	}
	return c, nil
}

// topicLevels reports whether s is one or more non-empty MQTT topic levels
// without wildcards.
func topicLevels(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsAny(s, "+#") && !slices.Contains(strings.Split(s, "/"), "")
}

// list splits a comma-separated list, trimming spaces and dropping empty items.
func list(s string) []string {
	var items []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// macSet parses the comma-separated MACs in env or, if it is empty, items.
// label names the setting in errors.
func macSet(label, env string, items []string) (map[bthome.MAC]bool, error) {
	if env != "" {
		items = list(env)
	}
	set := map[bthome.MAC]bool{}
	for _, item := range items {
		mac, err := parseMAC(item)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		set[mac] = true
	}
	return set, nil
}

func parseMAC(s string) (bthome.MAC, error) {
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return bthome.MAC{}, fmt.Errorf("%q is not a MAC address", s)
	}
	return bthome.MAC(hw), nil
}

type message struct {
	topic   string
	payload []byte
	retain  bool
	delay   bool // Home Assistant subscribes to a new event entity a moment after its discovery
}

// gateway turns readings into MQTT messages. messages is not safe for
// concurrent use; conn may be bumped from any goroutine.
//
// ponytail: devices are never pruned; without BLUGW_INCLUDE every BTHome
// device in range stays in memory. Add an age sweep if that ever matters.
type gateway struct {
	config
	conn    atomic.Uint64 // connection generation, bumped on every MQTT (re)connect
	devices map[bthome.MAC]*device

	mu       sync.Mutex // orders the "online" and "offline" status messages
	stopping bool       // no more "online"; guarded by mu
}

// device is the merged last-known state of one device.
type device struct {
	objs     map[string]bthome.Object // by state key; includes events, excludes 0xF0-0xF2
	model    uint16
	name     string
	firmware string
	config   []byte // last published discovery config
	gen      uint64 // connection generation config was published in
}

func newGateway(c config) *gateway {
	return &gateway{config: c, devices: map[bthome.MAC]*device{}}
}

func (g *gateway) status() string { return g.prefix + "/gateway/" + g.name + "/status" }

func (g *gateway) deviceTopic(m string) string { return g.prefix + "/device/" + m }

// messages merges r into its device's state and returns what to publish, in
// order: the discovery config when it is new or changed or the broker
// reconnected, the state, then any events.
func (g *gateway) messages(r blugw.Reading) []message {
	m := hex.EncodeToString(r.MAC[:])
	d := g.devices[r.MAC]
	if d == nil {
		d = &device{objs: map[string]bthome.Object{}}
		g.devices[r.MAC] = d
	}
	if r.Model != 0 {
		d.model = r.Model
	}
	if r.Name != "" {
		d.name = r.Name
	}

	var events []message
	seen := map[string]int{}
	for _, o := range r.Objects {
		k := o.Name()
		seen[k]++
		if n := seen[k]; n > 1 {
			k += "_" + strconv.Itoa(n)
		}
		_, known := d.objs[k]
		v := uint32(o.Value)
		switch o.ID {
		case 0xF0: // Reading.Model
		case 0xF1:
			d.firmware = fmt.Sprintf("%d.%d.%d.%d", v>>24, v>>16&0xFF, v>>8&0xFF, v&0xFF)
		case 0xF2:
			d.firmware = fmt.Sprintf("%d.%d.%d", v>>16, v>>8&0xFF, v&0xFF)
		default:
			d.objs[k] = o
		}
		if e := o.Event(); e != "" {
			p := map[string]any{"event_type": e}
			if o.ID == 0x3C {
				p["steps"] = o.Value
			}
			if o.ID == 0x3B && len(o.Raw) > 0 {
				p["args"] = hex.EncodeToString(o.Raw)
			}
			events = append(events, message{g.deviceTopic(m) + "/event/" + k, marshal(p), false, g.ha && !known})
		}
	}

	var msgs []message
	// ponytail: state is in memory only, so after a restart the config lists
	// just the keys seen since. A running HA keeps the omitted entities, but
	// once HA restarts they stay unavailable until their keys are seen again
	// (an H&T button until its next press). Reload the component set from the
	// retained config at startup if that bites.
	if g.ha {
		gen := g.conn.Load()
		if cfg := g.discovery(r.MAC, d); gen != d.gen || !bytes.Equal(cfg, d.config) {
			msgs = append(msgs, message{g.haPrefix + "/device/blugw_" + m + "/config", cfg, true, false})
			d.config, d.gen = cfg, gen
		}
	}

	s := map[string]any{
		"mac":       r.MAC.String(),
		"gateway":   g.name,
		"rssi":      r.RSSI,
		"time":      r.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		"encrypted": r.Encrypted,
	}
	if d.model != 0 {
		s["model_id"] = d.model
	}
	if n := g.names[r.MAC]; n != "" {
		s["name"] = n
	}
	if d.name != "" {
		s["local_name"] = d.name
	}
	if d.firmware != "" {
		s["firmware"] = d.firmware
	}
	for k, o := range d.objs {
		switch {
		case isEvent(o):
		case o.Binary():
			s[k] = o.Value != 0
		case o.ID == 0x53:
			s[k] = string(o.Raw)
		case o.ID == 0x54:
			s[k] = hex.EncodeToString(o.Raw)
		default:
			s[k] = o.Value
		}
	}
	msgs = append(msgs, message{g.deviceTopic(m), marshal(s), true, false})
	return append(msgs, events...)
}

func isEvent(o bthome.Object) bool { return o.ID >= 0x3A && o.ID <= 0x3C }

// marshal is json.Marshal without HTML escaping, so "H&T" stays readable.
func marshal(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(v) // cannot fail: only strings, bools, finite numbers, maps and slices
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
