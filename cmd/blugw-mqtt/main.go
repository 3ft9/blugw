// Command blugw-mqtt publishes BTHome v2 readings from Shelly BLU and other
// Bluetooth LE sensors to MQTT, optionally with Home Assistant discovery.
//
// It is configured with environment variables; run it with -h for the list.
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
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
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
)

const usage = `Usage: blugw-mqtt

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

Topics, with <mac> as 12 lower-case hex digits:

  <prefix>/gateway/<name>/status   online or offline (retained)
  <prefix>/device/<mac>            last known device state as JSON (retained)
  <prefix>/device/<mac>/event/<key>
                                   button, dimmer and command events as JSON
`

func main() {
	flag.Usage = func() { fmt.Fprint(flag.CommandLine.Output(), usage) }
	flag.Parse()
	if flag.NArg() > 0 || os.Getenv("BLUGW_MQTT_URL") == "" {
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := parseConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "blugw-mqtt:", err)
		os.Exit(2)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.level})))

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
			gen := g.conn.Add(1)
			// Read back the retained states and configs, so that keys not
			// seen since a restart are kept. The broker sends retained
			// messages right after the subscription. Anything later is live,
			// mostly this gateway's own publishes echoed back (MQTT 3.1.1 has
			// no no-local option), so it is ignored, and the subscription is
			// dropped once the burst is surely over.
			//
			// ponytail: a reading published between connecting and the broker
			// handling the subscription replaces its retained state before it
			// is read back, so that device starts afresh. Hold back publishing
			// until subscribed if that bites.
			topics := []string{g.deviceTopic("+")}
			if g.ha {
				topics = append(topics, g.haPrefix+"/device/+/config")
			}
			for _, t := range topics {
				c.Subscribe(t, g.qos, func(_ mqtt.Client, m mqtt.Message) {
					if m.Retained() {
						g.restore(m.Topic(), m.Payload())
					}
				})
			}
			time.AfterFunc(10*time.Second, func() {
				if g.conn.Load() == gen { // a reconnect has its own subscription and timer
					c.Unsubscribe(topics...)
				}
			})
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

func parseConfig(getenv func(string) string) (config, error) {
	c := config{
		url:      getenv("BLUGW_MQTT_URL"),
		user:     getenv("BLUGW_MQTT_USER"),
		password: getenv("BLUGW_MQTT_PASSWORD"),
		name:     getenv("BLUGW_NAME"),
		prefix:   cmp.Or(getenv("BLUGW_PREFIX"), "blugw"),
		haPrefix: cmp.Or(getenv("BLUGW_HA_PREFIX"), "homeassistant"),
		qos:      1,
		opts:     blugw.Options{Watchdog: 5 * time.Minute},
	}
	const wantURL = "want e.g. tcp://host:1883, ssl://host:8883 or ws://host:8080/mqtt"
	u, err := url.Parse(c.url)
	if err != nil {
		// Not wrapped: the error holds the URL, password and all.
		return c, errors.New("BLUGW_MQTT_URL: " + wantURL)
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
		return c, fmt.Errorf("BLUGW_MQTT_URL %q: %s", u.Redacted(), wantURL)
	}
	if c.name == "" {
		h, err := os.Hostname()
		if err != nil {
			return c, fmt.Errorf("BLUGW_NAME is not set and the host name is unknown: %w", err)
		}
		c.name = h
	}
	if !topicLevels(c.name) || strings.Contains(c.name, "/") {
		return c, fmt.Errorf("BLUGW_NAME %q: want one MQTT topic level, without / + #", c.name)
	}
	if !topicLevels(c.prefix) || strings.HasPrefix(c.prefix, "$") {
		return c, fmt.Errorf("BLUGW_PREFIX %q: want topic levels such as blugw or home/ble, without + #, empty levels or a leading $", c.prefix)
	}
	if !topicLevels(c.haPrefix) || strings.HasPrefix(c.haPrefix, "$") {
		return c, fmt.Errorf("BLUGW_HA_PREFIX %q: want topic levels such as homeassistant, without + #, empty levels or a leading $", c.haPrefix)
	}

	include, err := macSet(getenv, "BLUGW_INCLUDE")
	if err != nil {
		return c, err
	}
	exclude, err := macSet(getenv, "BLUGW_EXCLUDE")
	if err != nil {
		return c, err
	}
	if len(include) > 0 || len(exclude) > 0 {
		c.opts.Allow = func(m bthome.MAC) bool {
			return (len(include) == 0 || include[m]) && !exclude[m]
		}
	}

	for item := range strings.SplitSeq(getenv("BLUGW_NAMES"), ";") {
		if item = strings.TrimSpace(item); item == "" {
			continue
		}
		ms, name, _ := strings.Cut(item, "=")
		mac, err := parseMAC(strings.TrimSpace(ms))
		if name = strings.TrimSpace(name); err != nil || name == "" {
			return c, fmt.Errorf("BLUGW_NAMES: %q: want MAC=name", item)
		}
		if c.names == nil {
			c.names = map[bthome.MAC]string{}
		}
		c.names[mac] = name
	}

	for i, item := range list(getenv("BLUGW_KEYS")) {
		ms, ks, _ := strings.Cut(item, "=")
		mac, err := parseMAC(ms)
		key, kerr := hex.DecodeString(ks)
		if err != nil || kerr != nil || len(key) != 16 {
			// Keys are secret, and a malformed item may be all key.
			return c, fmt.Errorf("BLUGW_KEYS: item %d: want MAC=<32 hex digits>", i+1)
		}
		if c.opts.Keys == nil {
			c.opts.Keys = map[bthome.MAC][]byte{}
		}
		c.opts.Keys[mac] = key
	}

	if s := getenv("BLUGW_WATCHDOG"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < 0 {
			return c, fmt.Errorf("BLUGW_WATCHDOG %q: want a duration such as 5m, or 0 to disable", s)
		}
		c.opts.Watchdog = d
	}
	if s := getenv("BLUGW_HA"); s != "" {
		if c.ha, err = strconv.ParseBool(s); err != nil {
			return c, fmt.Errorf("BLUGW_HA %q: want true or false", s)
		}
	}
	if s := getenv("BLUGW_MQTT_QOS"); s != "" {
		q, err := strconv.ParseUint(s, 10, 8)
		if err != nil || q > 2 {
			return c, fmt.Errorf("BLUGW_MQTT_QOS %q: want 0, 1 or 2", s)
		}
		c.qos = byte(q)
	}
	if s := getenv("BLUGW_LOG_LEVEL"); s != "" {
		if err := c.level.UnmarshalText([]byte(s)); err != nil {
			return c, fmt.Errorf("BLUGW_LOG_LEVEL %q: want debug, info, warn or error", s)
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

func macSet(getenv func(string) string, name string) (map[bthome.MAC]bool, error) {
	set := map[bthome.MAC]bool{}
	for _, item := range list(getenv(name)) {
		mac, err := parseMAC(item)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
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

// gateway turns readings into MQTT messages. It is safe for concurrent use:
// messages runs on the scan goroutine and restore on paho's.
//
// ponytail: devices are never pruned; without BLUGW_INCLUDE every BTHome
// device in range stays in memory. Add an age sweep if that ever matters.
type gateway struct {
	config
	conn atomic.Uint64 // connection generation, bumped on every MQTT (re)connect

	devMu   sync.Mutex // guards devices and their contents
	devices map[bthome.MAC]*device

	mu       sync.Mutex // orders the "online" and "offline" status messages
	stopping bool       // no more "online"; guarded by mu
}

// device is the merged last-known state of one device.
type device struct {
	objs     map[string]bthome.Object  // by state key; includes events, excludes 0xF0-0xF2
	restored map[string]any            // retained state from before a restart; live keys override it
	cmps     map[string]map[string]any // retained discovery components from before a restart; current ones override them
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

// device returns mac's device, adding it if new. The caller holds devMu.
func (g *gateway) device(mac bthome.MAC) *device {
	d := g.devices[mac]
	if d == nil {
		d = &device{objs: map[string]bthome.Object{}}
		g.devices[mac] = d
	}
	return d
}

// messages merges r into its device's state and returns what to publish, in
// order: the discovery config when it is new or changed or the broker
// reconnected, the state, then any events.
func (g *gateway) messages(r blugw.Reading) []message {
	g.devMu.Lock()
	defer g.devMu.Unlock()
	m := hex.EncodeToString(r.MAC[:])
	d := g.device(r.MAC)
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
	for k, v := range d.restored {
		if _, ok := s[k]; !ok {
			s[k] = v
		}
	}
	msgs = append(msgs, message{g.deviceTopic(m), marshal(s), true, false})
	return append(msgs, events...)
}

// restore merges a retained state or discovery config that this gateway
// published, usually before a restart, into its device. Anything else is
// ignored.
func (g *gateway) restore(topic string, payload []byte) {
	var (
		m     string
		state map[string]any
		cfg   struct {
			Origin     struct{ Name string }
			Device     struct{ Identifiers []string }
			Components map[string]map[string]any
		}
	)
	// Configs first, as the prefixes may be the same.
	if s, ok := strings.CutPrefix(topic, g.haPrefix+"/device/blugw_"); ok {
		m, ok = strings.CutSuffix(s, "/config")
		if !ok || json.Unmarshal(payload, &cfg) != nil || cfg.Origin.Name != "blugw-mqtt" || !slices.Contains(cfg.Device.Identifiers, "blugw_"+m) {
			return
		}
	} else if m, ok = strings.CutPrefix(topic, g.prefix+"/device/"); !ok || json.Unmarshal(payload, &state) != nil || state["gateway"] != g.name {
		return
	}
	b, err := hex.DecodeString(m)
	if err != nil || len(b) != 6 || hex.EncodeToString(b) != m {
		return
	}
	mac := bthome.MAC(b)
	if g.opts.Allow != nil && !g.opts.Allow(mac) {
		return
	}

	g.devMu.Lock()
	defer g.devMu.Unlock()
	d := g.device(mac)
	if state != nil {
		delete(state, "name") // from BLUGW_NAMES, which may have changed
		d.restored = state
	} else {
		d.cmps = cfg.Components
	}
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
