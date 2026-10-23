// Package bthome decodes BTHome v2 Bluetooth LE advertisement service data,
// including AES-CCM encrypted payloads.
package bthome

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

// UUID is the 16-bit service data UUID that carries BTHome v2 payloads.
const UUID = 0xFCD2

// MAC is a Bluetooth device address in display order: MAC[0] is the first
// octet of "AA:BB:CC:DD:EE:FF".
type MAC [6]byte

// String returns the address in upper-case colon form.
func (m MAC) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
}

// Packet is a decoded BTHome v2 advertisement.
type Packet struct {
	MAC       MAC      // mac passed to Decode, or the address embedded in the payload when device-info bit 1 is set
	Encrypted bool     // device-info bit 0
	Trigger   bool     // device-info bit 2: device advertises on events, not at a fixed interval
	Counter   uint32   // encryption counter (little-endian on air); 0 when not encrypted
	Objects   []Object // payload order
}

// Object is one measurement, event or device-information object.
type Object struct {
	ID    byte
	Index int     // occurrence number of this ID within the packet, from 0 (Wall Switch 4 sends four 0x3A)
	Value float64 // scaled numeric value; event code for 0x3A; steps for 0x3C; opcode for 0x3B; 0 for 0x53/0x54
	Raw   []byte  // 0x53 text bytes, 0x54 raw bytes, 0x3B command args, 0x3C [event, steps]; nil otherwise
}

// Errors returned by Decode, possibly wrapped with detail.
var (
	// ErrNotBTHome means the data is empty or its version bits are not 2.
	ErrNotBTHome = errors.New("bthome: not BTHome v2")
	// ErrNoKey means the packet is encrypted and no key was given.
	ErrNoKey = errors.New("bthome: encrypted packet and no key")
	// ErrDecrypt means the MIC did not match: the key or the MAC is wrong.
	ErrDecrypt = errors.New("bthome: decryption failed (wrong key or MAC)")
	// ErrTruncated means the data ends part-way through a field.
	ErrTruncated = errors.New("bthome: truncated")
	// ErrUnknownObject means an object ID is not in the table, so its
	// length and everything after it cannot be decoded.
	ErrUnknownObject = errors.New("bthome: unknown object ID")
)

// Decode decodes BTHome v2 service data. data starts at the device-info
// byte, after the 2 UUID bytes. mac is the advertiser's address; it is part
// of the decryption nonce, and an address embedded in the payload overrides
// it. key is the 16-byte AES key used when the packet is encrypted. It is
// ignored for unencrypted packets: rejecting plaintext from a device that has
// a key (downgrade protection) is the caller's job.
//
// With ErrUnknownObject or ErrTruncated the returned Packet is still usable:
// it holds the objects decoded before the problem.
func Decode(data []byte, mac MAC, key []byte) (Packet, error) {
	if len(data) == 0 {
		return Packet{}, fmt.Errorf("%w: no data", ErrNotBTHome)
	}
	info := data[0]
	if v := info >> 5; v != 2 {
		return Packet{}, fmt.Errorf("%w: version %d", ErrNotBTHome, v)
	}
	p := Packet{MAC: mac, Encrypted: info&0x01 != 0, Trigger: info&0x04 != 0}
	payload := data[1:]

	// Bit 1 is reserved in the spec; bthome-ble reads it as "6 MAC bytes
	// follow, least significant first".
	if info&0x02 != 0 {
		if len(payload) < 6 {
			return p, fmt.Errorf("%w: embedded MAC", ErrTruncated)
		}
		for i := range p.MAC {
			p.MAC[i] = payload[5-i]
		}
		payload = payload[6:]
	}

	if p.Encrypted {
		if len(key) == 0 {
			return p, ErrNoKey
		}
		if len(key) != 16 {
			return p, fmt.Errorf("bthome: key is %d bytes, want 16", len(key))
		}
		if len(payload) < 8 {
			return p, fmt.Errorf("%w: encryption counter and MIC", ErrTruncated)
		}
		n := len(payload) - 8
		counter := payload[n : n+4]
		p.Counter = binary.LittleEndian.Uint32(counter)
		nonce := make([]byte, 0, 13)
		nonce = append(nonce, p.MAC[:]...)
		nonce = append(nonce, 0xD2, 0xFC, info) // UUID as on air, then the device-info byte as received
		nonce = append(nonce, counter...)
		var ok bool
		if payload, ok = openCCM(key, nonce, payload[:n], payload[n+4:]); !ok {
			return p, ErrDecrypt
		}
	}

	var err error
	p.Objects, err = decodeObjects(payload)
	return p, err
}

// openCCM decrypts and authenticates AES-128-CCM (RFC 3610) with a 13-byte
// nonce (L=2), a 4-byte MIC (M=4) and no associated data. The standard
// library has no CCM.
func openCCM(key, nonce, ciphertext, mic []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}

	// Counter block i is flags(L-1) | nonce | uint16 i. Block 0 masks the MIC.
	var a, s0 [aes.BlockSize]byte
	a[0] = 0x01
	copy(a[1:14], nonce)
	block.Encrypt(s0[:], a[:])
	a[15] = 1
	plain := make([]byte, len(ciphertext))
	cipher.NewCTR(block, a[:]).XORKeyStream(plain, ciphertext)

	// CBC-MAC over B0 = flags(M, L) | nonce | uint16 length, then the
	// zero-padded plaintext. The MAC is the first M bytes of the last block.
	b := make([]byte, aes.BlockSize+(len(plain)+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	b[0] = 0x09
	copy(b[1:14], nonce)
	binary.BigEndian.PutUint16(b[14:16], uint16(len(plain)))
	copy(b[aes.BlockSize:], plain)
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(b, b)
	tag := b[len(b)-aes.BlockSize:][:4]
	for i := range tag {
		tag[i] ^= s0[i]
	}
	if subtle.ConstantTimeCompare(tag, mic) != 1 {
		return nil, false
	}
	return plain, true
}

func decodeObjects(b []byte) ([]Object, error) {
	var objs []Object
	var seen [256]int
	for len(b) > 0 {
		id := b[0]
		t := &objTypes[id]
		if t.name == "" {
			return objs, fmt.Errorf("%w 0x%02X", ErrUnknownObject, id)
		}
		v := b[1:]
		n := t.size
		switch id {
		case 0x3B: // [length: low 5 bits = argument count][opcode][args]
			if len(v) > 0 {
				n += int(v[0] & 0x1F)
			}
		case 0x53, 0x54: // [length][bytes]
			if len(v) > 0 {
				n += int(v[0])
			}
		}
		if len(v) < n {
			return objs, fmt.Errorf("%w: object 0x%02X", ErrTruncated, id)
		}
		v = v[:n]

		o := Object{ID: id, Index: seen[id]}
		switch id {
		case 0x3B:
			o.Value = float64(v[1])
			o.Raw = append([]byte(nil), v[2:]...)
		case 0x3C:
			o.Value = float64(v[1])
			o.Raw = append([]byte(nil), v...)
		case 0x53, 0x54:
			o.Raw = append([]byte(nil), v[1:]...)
		default:
			o.Value = t.value(v)
		}
		objs = append(objs, o)
		seen[id]++
		b = b[1+n:]
	}
	return objs, nil
}

// Name returns the object's property name in snake_case, e.g.
// "temperature", or "" for an ID not in the table.
func (o Object) Name() string { return objTypes[o.ID].name }

// Unit returns the unit of Value, e.g. "°C", or "" if it has none.
func (o Object) Unit() string { return objTypes[o.ID].unit }

// Binary reports whether the object is a binary sensor, whose Value is 0 or 1.
// Most are 1 for on/detected; lock 1 means unlocked and safety 1 means safe.
func (o Object) Binary() bool {
	return o.ID >= 0x0F && o.ID <= 0x2D && (o.ID < 0x12 || o.ID > 0x14) // 0x12-0x14 are co2, tvoc, moisture
}

// Event returns the event name of a button (0x3A), command (0x3B) or dimmer
// (0x3C) object. It returns "" for event code 0x00 (none) on buttons and
// dimmers, for unknown codes and for non-event objects.
func (o Object) Event() string {
	switch o.ID {
	case 0x3A:
		switch o.Value {
		case 0x01:
			return "press"
		case 0x02:
			return "double_press"
		case 0x03:
			return "triple_press"
		case 0x04:
			return "long_press"
		case 0x05:
			return "long_double_press"
		case 0x06:
			return "long_triple_press"
		case 0x80, 0xFE: // older Shelly BLU firmware sends 0xFE for hold
			return "hold_press"
		}
	case 0x3B:
		switch o.Value {
		case 0x00:
			return "off"
		case 0x01:
			return "on"
		case 0x02:
			return "toggle"
		case 0x03:
			return "step_up"
		case 0x04:
			return "step_down"
		}
	case 0x3C:
		if len(o.Raw) == 2 {
			switch o.Raw[0] {
			case 0x01:
				return "rotate_left"
			case 0x02:
				return "rotate_right"
			}
		}
	}
	return ""
}

type objType struct {
	name     string
	unit     string
	size     int // value bytes; for 0x3B, 0x53 and 0x54 the fixed bytes before the variable part
	signed   bool
	num, den int // factor as a fraction so that, e.g., 195 * 1/10 is exactly 19.5
}

// value decodes a little-endian integer and applies the factor.
func (t *objType) value(v []byte) float64 {
	var u uint64
	for i := len(v) - 1; i >= 0; i-- {
		u = u<<8 | uint64(v[i])
	}
	x := float64(u)
	if t.signed {
		shift := 64 - 8*len(v)
		x = float64(int64(u<<shift) >> shift)
	}
	return x * float64(t.num) / float64(t.den)
}

// objTypes is the BTHome v2 object table from https://bthome.io/format/,
// cross-checked against MEAS_TYPES in bthome-ble's src/bthome_ble/const.py.
// Names are the spec's property names in snake_case, except that binary
// sensors sharing a name with a numeric property (battery, power, gas,
// moisture) get a suffix for their true state.
var objTypes = [256]objType{
	0x00: {"packet_id", "", 1, false, 1, 1},
	0x01: {"battery", "%", 1, false, 1, 1},
	0x02: {"temperature", "°C", 2, true, 1, 100},
	0x03: {"humidity", "%", 2, false, 1, 100},
	0x04: {"pressure", "hPa", 3, false, 1, 100},
	0x05: {"illuminance", "lx", 3, false, 1, 100},
	0x06: {"mass", "kg", 2, false, 1, 100},
	0x07: {"mass", "lb", 2, false, 1, 100},
	0x08: {"dewpoint", "°C", 2, true, 1, 100},
	0x09: {"count", "", 1, false, 1, 1},
	0x0A: {"energy", "kWh", 3, false, 1, 1000},
	0x0B: {"power", "W", 3, false, 1, 100},
	0x0C: {"voltage", "V", 2, false, 1, 1000},
	0x0D: {"pm25", "µg/m³", 2, false, 1, 1},
	0x0E: {"pm10", "µg/m³", 2, false, 1, 1},
	0x0F: {"generic_boolean", "", 1, false, 1, 1},
	0x10: {"power_on", "", 1, false, 1, 1},
	0x11: {"opening", "", 1, false, 1, 1},
	0x12: {"co2", "ppm", 2, false, 1, 1},
	0x13: {"tvoc", "µg/m³", 2, false, 1, 1},
	0x14: {"moisture", "%", 2, false, 1, 100},
	0x15: {"battery_low", "", 1, false, 1, 1},
	0x16: {"battery_charging", "", 1, false, 1, 1},
	0x17: {"carbon_monoxide", "", 1, false, 1, 1},
	0x18: {"cold", "", 1, false, 1, 1},
	0x19: {"connectivity", "", 1, false, 1, 1},
	0x1A: {"door", "", 1, false, 1, 1},
	0x1B: {"garage_door", "", 1, false, 1, 1},
	0x1C: {"gas_detected", "", 1, false, 1, 1},
	0x1D: {"heat", "", 1, false, 1, 1},
	0x1E: {"light", "", 1, false, 1, 1},
	0x1F: {"lock", "", 1, false, 1, 1}, // 1 = unlocked
	0x20: {"moisture_detected", "", 1, false, 1, 1},
	0x21: {"motion", "", 1, false, 1, 1},
	0x22: {"moving", "", 1, false, 1, 1},
	0x23: {"occupancy", "", 1, false, 1, 1},
	0x24: {"plug", "", 1, false, 1, 1},
	0x25: {"presence", "", 1, false, 1, 1},
	0x26: {"problem", "", 1, false, 1, 1},
	0x27: {"running", "", 1, false, 1, 1},
	0x28: {"safety", "", 1, false, 1, 1}, // 1 = safe
	0x29: {"smoke", "", 1, false, 1, 1},
	0x2A: {"sound", "", 1, false, 1, 1},
	0x2B: {"tamper", "", 1, false, 1, 1},
	0x2C: {"vibration", "", 1, false, 1, 1},
	0x2D: {"window", "", 1, false, 1, 1},
	0x2E: {"humidity", "%", 1, false, 1, 1},
	0x2F: {"moisture", "%", 1, false, 1, 1},
	0x3A: {"button", "", 1, false, 1, 1},
	0x3B: {"command", "", 2, false, 1, 1},
	0x3C: {"dimmer", "", 2, false, 1, 1},
	0x3D: {"count", "", 2, false, 1, 1},
	0x3E: {"count", "", 4, false, 1, 1},
	0x3F: {"rotation", "°", 2, true, 1, 10},
	0x40: {"distance", "mm", 2, false, 1, 1},
	0x41: {"distance", "m", 2, false, 1, 10},
	0x42: {"duration", "s", 3, false, 1, 1000},
	0x43: {"current", "A", 2, false, 1, 1000},
	0x44: {"speed", "m/s", 2, false, 1, 100},
	0x45: {"temperature", "°C", 2, true, 1, 10},
	0x46: {"uv_index", "", 1, false, 1, 10},
	0x47: {"volume", "L", 2, false, 1, 10},
	0x48: {"volume", "mL", 2, false, 1, 1},
	0x49: {"volume_flow_rate", "m³/h", 2, false, 1, 1000},
	0x4A: {"voltage", "V", 2, false, 1, 10},
	0x4B: {"gas", "m³", 3, false, 1, 1000},
	0x4C: {"gas", "m³", 4, false, 1, 1000},
	0x4D: {"energy", "kWh", 4, false, 1, 1000},
	0x4E: {"volume", "L", 4, false, 1, 1000},
	0x4F: {"water", "L", 4, false, 1, 1000},
	0x50: {"timestamp", "", 4, false, 1, 1}, // seconds since the Unix epoch
	0x51: {"acceleration", "m/s²", 2, false, 1, 1000},
	0x52: {"gyroscope", "°/s", 2, false, 1, 1000},
	0x53: {"text", "", 1, false, 1, 1},
	0x54: {"raw", "", 1, false, 1, 1},
	0x55: {"volume_storage", "L", 4, false, 1, 1000},
	0x56: {"conductivity", "µS/cm", 2, false, 1, 1},
	0x57: {"temperature", "°C", 1, true, 1, 1},
	0x58: {"temperature", "°C", 1, true, 35, 100},
	0x59: {"count", "", 1, true, 1, 1},
	0x5A: {"count", "", 2, true, 1, 1},
	0x5B: {"count", "", 4, true, 1, 1},
	0x5C: {"power", "W", 4, true, 1, 100},
	0x5D: {"current", "A", 2, true, 1, 1000},
	0x5E: {"direction", "°", 2, false, 1, 100},
	0x5F: {"precipitation", "mm", 2, false, 1, 10},
	0x60: {"channel", "", 1, false, 1, 1},
	0x61: {"rotational_speed", "rpm", 2, false, 1, 1},
	0x62: {"speed", "m/s", 4, true, 1, 1000000},
	0x63: {"acceleration", "m/s²", 4, true, 1, 1000000},
	0x64: {"light_level", "", 1, false, 1, 1}, // 0 dark, 1 twilight, 2 bright
	0x65: {"settings_revision", "", 1, false, 1, 1},
	0xF0: {"device_type_id", "", 2, false, 1, 1},
	0xF1: {"firmware_version", "", 4, false, 1, 1}, // major in the most significant byte
	0xF2: {"firmware_version", "", 3, false, 1, 1},
}
