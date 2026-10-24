# blugw

blugw receives BTHome v2 Bluetooth LE advertisements from Shelly BLU devices
and any other BTHome v2 device, and publishes them to MQTT. It has three
parts:

- `bthome` (`github.com/3ft9/blugw/bthome`): a BTHome v2 decoder, including AES-CCM decryption. It uses only
  the standard library and works on its own.
- `blugw` (`github.com/3ft9/blugw/blugw`): a scanner that turns advertisements into deduplicated, decoded
  readings. It uses [tinygo.org/x/bluetooth](https://github.com/tinygo-org/bluetooth).
- `cmd/blugw-mqtt`: the gateway binary. It publishes readings to an MQTT
  broker, with optional Home Assistant discovery.

## Install

Go 1.25 or later is required.

```sh
go install github.com/3ft9/blugw/cmd/blugw-mqtt@latest
```

To cross-compile for a Raspberry Pi, build without cgo:

```sh
git clone https://github.com/3ft9/blugw && cd blugw
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/blugw-mqtt          # 64-bit OS
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build ./cmd/blugw-mqtt    # 32-bit OS
```

Use `GOARM=6` for a Pi Zero or Pi 1. On Linux, blugw talks to BlueZ
(`bluetoothd`) over D-Bus and needs no C libraries.

On macOS, blugw uses CoreBluetooth, which needs cgo. cgo is on by default, but
it needs the Xcode Command Line Tools, so build blugw-mqtt on a Mac.

macOS asks for Bluetooth permission for the app that runs the binary, such as
Terminal. If permission is denied, blugw-mqtt exits at startup. You can grant
it under System Settings > Privacy & Security > Bluetooth.

## Configuration

blugw-mqtt reads its configuration from environment variables and, optionally,
a [configuration file](#configuration-file). Run `blugw-mqtt -h` to print the
list.

| Variable | Default | Meaning |
| --- | --- | --- |
| `BLUGW_MQTT_URL` | required | Broker URL: `tcp://host:1883` or `mqtt://` (plain), `ssl://host:8883`, `tls://` or `mqtts://` (TLS), `ws://host:8080/mqtt` or `wss://` (WebSocket), or `unix:///path/to/socket`. TCP and TLS URLs need a port. |
| `BLUGW_MQTT_USER` | | Broker user name. |
| `BLUGW_MQTT_PASSWORD` | | Broker password. |
| `BLUGW_MQTT_QOS` | `1` | MQTT QoS for every message: `0`, `1` or `2`. See [Delivery](#delivery). |
| `BLUGW_NAME` | host name | Gateway name. It is used in the status topic and the MQTT client ID `blugw-<name>`. It must be one topic level, so no `/`, `+` or `#`. |
| `BLUGW_PREFIX` | `blugw` | Topic prefix. One or more topic levels, such as `home/ble`. No `+`, `#`, empty levels or leading `$`. |
| `BLUGW_INCLUDE` | | Comma-separated MACs. When set, only these devices are processed. |
| `BLUGW_EXCLUDE` | | Comma-separated MACs that are never processed. |
| `BLUGW_NAMES` | | Semicolon-separated `MAC=name` pairs, such as `38:39:8F:87:2B:3E=Office;7C:C6:B6:09:89:8F=Garden`. Names appear in the state JSON and as Home Assistant device names. Shelly app names are not available over Bluetooth, so they have to be set here. |
| `BLUGW_KEYS` | | Comma-separated `MAC=key` pairs for encrypted devices. Each key is 32 hex digits. |
| `BLUGW_WATCHDOG` | `5m` | Restart scanning when no BTHome advertisement has arrived for this long, as a Go duration. `0` disables it. |
| `BLUGW_HA` | `false` | Publish Home Assistant MQTT discovery: `true` or `false`. |
| `BLUGW_HA_PREFIX` | `homeassistant` | Home Assistant discovery prefix. |
| `BLUGW_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. Logs go to stderr. At `debug`, every published message is logged. |

MACs can be written as `38:39:8F:87:2B:3E` or `38-39-8f-87-2b-3e`, in any
case. Spaces around list items and empty items are ignored. The allowed
devices are the `BLUGW_INCLUDE` list (or every device when it is empty), minus
the `BLUGW_EXCLUDE` list.

For an invalid configuration, blugw-mqtt prints the problem and exits with
status 2. If it cannot enable the Bluetooth adapter, it exits with status 1.

### Configuration file

`blugw-mqtt -config /etc/blugw-mqtt.yaml` reads the same settings from a YAML
file. Every key is optional and matches one variable:

```yaml
mqtt:
  url: tcp://broker.lan:1883   # BLUGW_MQTT_URL, required here or in the environment
  user: blugw                  # BLUGW_MQTT_USER
  password: secret             # BLUGW_MQTT_PASSWORD
  qos: 1                       # BLUGW_MQTT_QOS
name: pi                       # BLUGW_NAME
prefix: blugw                  # BLUGW_PREFIX
include:                       # BLUGW_INCLUDE
  - 38:39:8F:87:2B:3E
  - 7C:C6:B6:09:89:8F
exclude: []                    # BLUGW_EXCLUDE
names:                         # BLUGW_NAMES
  38:39:8F:87:2B:3E: Office
  7C:C6:B6:09:89:8F: Garden; by the shed
keys:                          # BLUGW_KEYS
  38:39:8F:87:2B:3E: 00112233445566778899aabbccddeeff
watchdog: 5m                   # BLUGW_WATCHDOG
homeassistant:
  enabled: true                # BLUGW_HA
  prefix: homeassistant        # BLUGW_HA_PREFIX
log_level: info                # BLUGW_LOG_LEVEL
```

- An environment variable that is set and not empty overrides the file's
  value for the same setting, so secrets such as the MQTT password can stay in
  the environment. A list or map variable replaces the file's whole list or
  map.
- Values are read as written, so MACs and keys need no quotes, even when they
  are all digits, and names may contain `;`, `=` and `,`. Quote a name or
  password that YAML would misread: one that starts with punctuation such as
  `*`, `&`, `!`, `'` or `"`, or contains ` #` or `: `. Inside single quotes
  everything is as written, except that `''` stands for one `'`.
- `homeassistant.enabled` takes `true` or `false`, not `yes` or `no`.
- Unknown keys are an error, so a misspelt key does not silently leave its
  default in place.
- If the file holds a password (in `mqtt.password` or `mqtt.url`) or keys and
  is readable by its group or others, blugw-mqtt logs a warning. Give it mode
  600.

## MQTT topics and payloads

In the topics below, `blugw` is the default `BLUGW_PREFIX`, and `<mac>` is
the device MAC as 12 lower-case hex digits, such as `38398f872b3e`. Every
message is published with QoS `BLUGW_MQTT_QOS` (default 1).

| Topic | Payload | Retained |
| --- | --- | --- |
| `blugw/gateway/<name>/status` | `online` or `offline` | yes |
| `blugw/device/<mac>` | device state, JSON | yes |
| `blugw/device/<mac>/event/<key>` | event, JSON | no |

### Gateway status

`online` is published on every connection to the broker. `offline` is
published on a clean shutdown (SIGINT or SIGTERM), and the broker publishes it
as the last will if the connection drops.

### Device state

The state is published after every reading. This is a Shelly BLU H&T reading
(sent as one line, formatted here):

```json
{
  "battery": 82,
  "encrypted": false,
  "gateway": "pi",
  "humidity": 54,
  "local_name": "SBHT-003C",
  "mac": "38:39:8F:87:2B:3E",
  "model_id": 3,
  "name": "Office",
  "packet_id": 214,
  "rssi": -66,
  "temperature": 20,
  "time": "2026-10-23T18:23:41.787Z"
}
```

| Key | Meaning |
| --- | --- |
| `mac` | Device MAC. |
| `gateway` | `BLUGW_NAME` of the receiver that published the state. |
| `rssi` | Signal strength of the latest reading, in dBm. |
| `time` | When the latest reading was received, in RFC 3339 UTC with milliseconds. |
| `encrypted` | Whether the latest reading was encrypted. |
| `model_id` | Shelly model ID, such as 3 for the BLU H&T. Omitted until known. |
| `name` | Name from `BLUGW_NAMES`. Omitted if the device has none. |
| `local_name` | Advertised local name, which for Shelly devices is the model code. Omitted until known. |
| `firmware` | Firmware version from a device-info packet, such as `1.0.23.0`. Omitted until known. |

Every other key is a BTHome object, named in snake_case as in the
[BTHome spec](https://bthome.io/format/): `temperature`, `humidity`,
`illuminance`, `motion`, `window`, `rotation`, `packet_id` and so on. A binary
object that shares its name with a numeric one gets a suffix: `battery_low`,
`power_on`, `gas_detected` and `moisture_detected`.

If one packet holds several objects with the same name, the second gets the
key `temperature_2`, the third `temperature_3`, and so on, in packet order.

The value types are:

- Numbers are scaled to the unit in the spec.
- Binary objects are `true` or `false`, with their BTHome meaning. For
  example, `lock` `true` means unlocked and `safety` `true` means safe.
- `text` is a string, and `raw` is a hex string.

The state holds the last known value of every key. A new reading only
overwrites the keys it carries. For example, the device-info packet that
Shelly devices send every 6 hours holds only `packet_id`, `battery`, the model
and the firmware, so `temperature` and `humidity` stay in the state.

Event objects (button, dimmer, command) are not part of the state. Neither are
the device type and firmware objects, which become `model_id` and `firmware`.

### Events

Each button, dimmer or command event is published to
`blugw/device/<mac>/event/<key>`. The key follows the same rules as the state keys.
For example, a press of the third button on a BLU Wall Switch 4 is published to
`.../event/button_3`. A button position that reports no event publishes
nothing.

This is a press of a Shelly BLU Button1:

```
blugw/device/b43522f53da4/event/button  {"event_type":"press"}
```

| Object | `event_type` | Extra fields |
| --- | --- | --- |
| `button` | `press`, `double_press`, `triple_press`, `long_press`, `long_double_press`, `long_triple_press`, `hold_press` | |
| `dimmer` | `rotate_left`, `rotate_right` | `steps`: number of steps |
| `command` | `off`, `on`, `toggle`, `step_up`, `step_down` | `args`: argument bytes as hex, when there are any |

### Delivery

blugw-mqtt connects in the background and keeps retrying, so scanning starts
even if the broker is down. While it is disconnected, messages are dropped, not
queued. The retained state comes back with the next reading, but events that
happen during the outage are lost. Messages that were sent but not
acknowledged when a connection dropped are resent after it reconnects, so a
few events may arrive late. With `BLUGW_MQTT_QOS=0` nothing is resent: those
events are lost instead of late.

## Home Assistant

Set `BLUGW_HA=true` to publish
[MQTT device discovery](https://www.home-assistant.io/integrations/mqtt/),
which needs Home Assistant 2024.11 or later. The Home Assistant MQTT
integration must use the same broker. Each device gets one retained config at
`homeassistant/device/blugw_<mac>/config`.

Each device takes its name from `BLUGW_NAMES`. Without one, it is named after
its Shelly model plus the last four hex digits of its MAC, such as
`BLU H&T 2B3E`; devices that are not known Shelly models use their advertised
name instead, or `BTHome` if they have none. The device info
shows the manufacturer and model (for Shelly models), the model ID (the
advertised name, such as `SBHT-003C`) and the firmware version.

Each state key becomes an entity:

- Numeric, text and raw values become sensors. Numeric sensors get a Home
  Assistant device class and state class where one matches the unit.
- Binary values become binary sensors with the matching device class. Values
  follow Home Assistant's meaning of on and off, so BTHome `safety` is
  inverted (BTHome 1 means safe, while in Home Assistant, on means unsafe).
- Buttons, dimmers and commands become event entities. They are fed from the
  event topics.
- `rssi` and `packet_id` become diagnostic sensors.

A BLU H&T shows Temperature, Humidity and Battery, with Rssi and Packet Id
under diagnostics. Its Button entity appears after the first press: entities
are added as their keys are first seen, and the config is republished when the
set of keys or the device info changes. The first event for each event key after
startup is published about 2 seconds late, so that Home Assistant has time to
subscribe to a new event entity.

Every entity's availability follows the gateway status topic. When the gateway
stops, or its connection to the broker drops, its devices show as unavailable.
After every reconnect, each device's config is republished with its next
reading, in case the broker lost its retained messages.

Setting `BLUGW_HA=false` does not remove configs that were already published.
To remove one, publish an empty retained message to its topic:

```sh
mosquitto_pub -h broker -r -n -t homeassistant/device/blugw_38398f872b3e/config
```

## Running several receivers

One receiver may not reach every device. To cover a larger area, run several
receivers and split the devices between them with `BLUGW_INCLUDE`, the way
devices are assigned to gateways in the Shelly app. Each device should be on
exactly one receiver's list, and each receiver needs its own `BLUGW_NAME`. Two
clients with the same client ID keep disconnecting each other.

```sh
# hall
BLUGW_NAME=hall BLUGW_INCLUDE=38:39:8F:87:2B:3E,B0:C7:DE:42:1F:D5
# garage
BLUGW_NAME=garage BLUGW_INCLUDE=7C:C6:B6:09:89:8F
```

When receivers overlap, every receiver that hears a device publishes its
readings:

- Events are published once per receiver, so one button press runs its
  automations several times.
- `gateway` and `rssi` in the state flip between receivers.
- In Home Assistant, the device's availability follows whichever receiver
  published its config last.

To decide which receiver should own a device, compare its `rssi` on each
receiver by running them briefly without `BLUGW_INCLUDE`.

## Encrypted devices

Encrypted BTHome devices need their AES key:

```sh
BLUGW_KEYS=38:39:8F:8C:77:DA=<32 hex digits>,7C:C6:B6:75:39:3C=<32 hex digits>
```

For a Shelly BLU device, Shelly documents reading the key from the device
itself: pair with it in Shelly's BLE Debug app (this needs the PIN that was
set when encryption was enabled) and read the 16-byte "Encryption key"
characteristic. A Shelly gateway that already has the key will not reveal it.
If that is more trouble than it is worth, the Shelly app's Decrypt option turns
encryption off. The keys are secrets, so keep the environment or configuration
file readable only by root (see [Deployment](#deployment)).

blugw handles encrypted packets as follows:

- An encrypted packet from a device without a key is dropped, with one warning
  per device.
- A packet that fails to decrypt, because the key is wrong, is dropped with a
  warning.
- Once a device has a key, its unencrypted packets are dropped. If you turn
  encryption off on the device, remove its key too.
- Replay protection is strict. The encryption counter must increase: a packet
  with the same counter as the last one is treated as a repeat, and a packet
  with a lower counter is dropped with a warning. The last counters are kept in
  memory, so a lower counter keeps being dropped until the process restarts.

> **Keep a time beacon in range of encrypted Shelly BLU devices.** This is
> observed behaviour, not documented by Shelly. Shelly BLU devices that hear
> a time beacon from a Gen2 or later mains-powered Shelly (for example a Plug
> with its Bluetooth gateway enabled) appear to use Unix time as their
> encryption counter, which survives battery changes. Without a beacon, the
> counter may reset, for example after a battery swap. blugw then drops that
> device's readings until it is restarted. The battery-swap case is untested.

## Deployment

### systemd

blugw-mqtt does not need root. It talks to `bluetoothd` over D-Bus, and BlueZ's
D-Bus policy allows any user to do that. Put the configuration in
`/etc/blugw-mqtt.env`, owned by root with mode 600:

```sh
BLUGW_MQTT_URL=tcp://broker.lan:1883
BLUGW_MQTT_USER=blugw
BLUGW_MQTT_PASSWORD=secret
BLUGW_HA=true
```

Write it without quotes, so that Docker's `--env-file` can read the same file.
Then create `/etc/systemd/system/blugw-mqtt.service`:

```ini
[Unit]
Description=BTHome to MQTT gateway
After=bluetooth.service

[Service]
ExecStart=/usr/local/bin/blugw-mqtt
EnvironmentFile=/etc/blugw-mqtt.env
DynamicUser=yes
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now blugw-mqtt
journalctl -u blugw-mqtt -f
```

systemd reads `EnvironmentFile` before it drops privileges, so the service can
use the file without being able to read it. Single variables can also be set
with `Environment=` lines.

To use a [configuration file](#configuration-file) instead, put it in
`/etc/blugw-mqtt.yaml`, also owned by root with mode 600, and replace the
`ExecStart` and `EnvironmentFile` lines with:

```ini
ExecStart=/usr/local/bin/blugw-mqtt -config ${CREDENTIALS_DIRECTORY}/blugw-mqtt.yaml
LoadCredential=blugw-mqtt.yaml:/etc/blugw-mqtt.yaml
```

The service cannot read the file itself, so `LoadCredential` (systemd 247 or
later) gives it a private copy that only the service can read.

### Docker

Use a binary built with `CGO_ENABLED=0`. It needs only the D-Bus socket, not
`--privileged` or host networking:

```sh
docker run -d --name blugw-mqtt --restart=always \
  -v /run/dbus:/run/dbus:ro -v /usr/local/bin/blugw-mqtt:/blugw-mqtt:ro \
  --env-file /etc/blugw-mqtt.env -e BLUGW_NAME=pi \
  gcr.io/distroless/static-debian13 /blugw-mqtt
```

Set `BLUGW_NAME`, because a container's host name is its container ID.

### macOS

To run blugw-mqtt in the background, use a LaunchAgent in
`~/Library/LaunchAgents`, with the configuration in its `EnvironmentVariables`
or in a file passed with `-config` in its `ProgramArguments`.
It runs only while that user is logged in. LaunchDaemons cannot use Bluetooth.

## Using the packages

Decoding service data with `bthome`:

```go
// Service data for UUID 0xFCD2, from the device-info byte on.
data, _ := hex.DecodeString("4400d601522e3645c800")
mac := bthome.MAC{0x38, 0x39, 0x8F, 0x87, 0x2B, 0x3E}

p, err := bthome.Decode(data, mac, nil) // nil key: not encrypted
if err != nil {
	log.Fatal(err)
}
for _, o := range p.Objects {
	fmt.Println(o.Name(), o.Value, o.Unit())
}
// packet_id 214
// battery 82 %
// humidity 54 %
// temperature 20 °C
```

Notes on `bthome.Decode`:

- The MAC is part of the decryption nonce, so it is required for encrypted
  packets. A MAC embedded in the payload overrides it.
- With `ErrUnknownObject` or `ErrTruncated`, the returned packet still holds
  the objects decoded before the problem.
- `Object.Event` names button, dimmer and command events.
- Replay and downgrade checks are left to the caller.

Scanning with `blugw`:

```go
ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
defer stop()

opts := blugw.Options{Watchdog: 5 * time.Minute}
err := blugw.Scan(ctx, opts, func(r blugw.Reading) {
	// Called from one goroutine; return quickly.
	fmt.Println(r.Time.Format(time.TimeOnly), r.MAC, r.Name, r.RSSI)
	for _, o := range r.Objects {
		if e := o.Event(); e != "" {
			fmt.Println(" ", o.Name(), o.Index, e)
			continue
		}
		fmt.Println(" ", o.Name(), o.Value, o.Unit())
	}
})
if ctx.Err() == nil {
	log.Fatal(err)
}
```

`Scan` blocks until `ctx` is done or the adapter cannot be enabled. It works as
follows:

- Shelly devices repeat each advertisement for about a second. `Scan` reports
  each reading once. It drops identical bytes, and packet IDs that are not
  newer than one seen in the last 4 seconds.
- It applies the replay and downgrade rules above for `Options.Keys`, and
  filters devices with `Options.Allow`.
- `Reading` adds the Shelly model ID, the local name, the RSSI and the time
  received to the decoded packet.
- If `fn` is slow, advertisements are dropped and a warning is logged.
- `Scan` logs through `log/slog`'s default logger.

## Limitations

- **Windows**: blugw builds, but tinygo bluetooth v0.16.0 does not deliver
  service data on Windows, so no readings arrive.
- **Linux**: blugw has only been tested on macOS. The Linux build is
  cross-compiled but has not yet been run against real devices.
- **macOS**: CoreBluetooth hides device addresses. blugw learns MACs from
  Shelly manufacturer data or from a MAC embedded in the BTHome payload, so
  other devices are not reported on macOS.
- **Repeated bytes**: a device without a packet ID that sends identical bytes
  again is reported only when the bytes change.
- **BTHome v1**: not supported.
- **State is in memory**: after a restart, the state and the Home Assistant
  config hold only keys seen since. Entities whose keys have not been seen yet,
  such as an H&T button until its next press, may show as unavailable after
  Home Assistant restarts.
- **Listening only**: blugw does not configure devices or send them commands.

## Roadmap

v2 will let blugw act as a Shelly time-beacon source on Linux, so that
encrypted devices keep Unix-time counters without a mains Shelly nearby. This
is not possible on macOS, where CoreBluetooth cannot advertise manufacturer
data.

## License

MIT. See [LICENSE](LICENSE).
