// Package blugw scans Bluetooth LE for BTHome v2 devices, such as Shelly BLU
// sensors, and reports decoded readings.
package blugw

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/3ft9/blugw/bthome"
	"tinygo.org/x/bluetooth"
)

// Reading is a decoded BTHome advertisement plus what is known about its sender.
type Reading struct {
	bthome.Packet
	Model uint16    // Shelly model ID (0x0003 = BLU H&T) from manufacturer data or object 0xF0; 0 if unknown
	Name  string    // advertised local name; may be empty
	RSSI  int16     // signal strength in dBm
	Time  time.Time // when the advertisement was received
}

// Options configures Scan.
type Options struct {
	Keys     map[bthome.MAC][]byte // AES-128 keys for encrypted devices; unencrypted packets from these MACs are dropped
	Watchdog time.Duration         // restart scanning when no BTHome advert has arrived for this long; 0 disables
	Allow    func(bthome.MAC) bool // reports whether to process a device; nil allows all

	// TimeBeacon broadcasts the Shelly time beacon, with time zone details
	// from time.Local, so that encrypted Shelly BLU devices use Unix time as
	// their encryption counter without a mains-powered Shelly in range. It
	// broadcasts only while the system clock is NTP-synchronised. Linux
	// only: elsewhere Scan returns an error wrapping errors.ErrUnsupported.
	TimeBeacon bool
}

const (
	shellyCompany = 0x0BA9
	dedupWindow   = 4 * time.Second
	restartDelay  = 5 * time.Second
)

var bthomeUUID = bluetooth.New16BitUUID(bthome.UUID)

var monoStart = time.Now()

// mono returns nanoseconds on the monotonic clock, which unlike wall time
// does not jump when the system clock is set.
func mono() int64 { return int64(time.Since(monoStart)) }

// Scan blocks until ctx is done (returns ctx.Err()) or the adapter cannot be
// enabled. fn is called sequentially from one goroutine and should return
// quickly.
func Scan(ctx context.Context, opts Options, fn func(Reading)) error {
	if opts.TimeBeacon && runtime.GOOS != "linux" {
		// It needs BlueZ; CoreBluetooth cannot advertise manufacturer data.
		return fmt.Errorf("blugw: time beacon on %s: %w", runtime.GOOS, errors.ErrUnsupported)
	}
	a := bluetooth.DefaultAdapter
	if err := a.Enable(); err != nil {
		return err
	}

	var (
		ch    = make(chan advert, 256)
		drops atomic.Uint64
		last  atomic.Int64 // mono() of the last BTHome advert, for the watchdog
	)
	// The callback must never block: on Linux a slow callback makes godbus
	// park every D-Bus signal in a new goroutine, and on darwin it holds up the
	// CoreBluetooth queue. ch is never closed because darwin may still deliver
	// queued results after Scan returns.
	cb := func(_ *bluetooth.Adapter, r bluetooth.ScanResult) {
		if r.AdvertisementPayload == nil {
			return
		}
		var ad advert
		for _, sd := range r.ServiceData() {
			if sd.UUID == bthomeUUID {
				ad.data = bytes.Clone(sd.Data)
			}
		}
		for _, md := range r.ManufacturerData() {
			if md.CompanyID == shellyCompany {
				ad.mfr = bytes.Clone(md.Data)
			}
		}
		if ad.data == nil && ad.mfr == nil {
			return
		}
		ad.time = time.Now()
		if ad.data != nil {
			last.Store(mono())
		}
		ad.addr, ad.name, ad.rssi = r.Address.String(), r.LocalName(), r.RSSI
		select {
		case ch <- ad:
		default:
			drops.Add(1)
		}
	}

	var wg sync.WaitGroup
	wg.Go(func() { run(ctx, a, cb, &last, opts.Watchdog) })
	if opts.TimeBeacon {
		wg.Go(func() { beacon(ctx) })
	}

	s := scanner{keys: opts.Keys, allow: opts.Allow, devices: map[string]*device{}, counters: map[bthome.MAC]uint32{}}
	var dropLogged time.Time
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case ad := <-ch:
			if r, ok := s.handle(ad); ok {
				fn(r)
			}
			if drops.Load() > 0 && time.Since(dropLogged) >= time.Minute {
				slog.Warn("blugw: adverts dropped because fn is too slow", "count", drops.Swap(0))
				dropLogged = time.Now()
			}
		}
	}
}

// run scans until ctx is done, restarting whenever the scan ends by itself or
// the watchdog stops it.
func run(ctx context.Context, a *bluetooth.Adapter, cb func(*bluetooth.Adapter, bluetooth.ScanResult), last *atomic.Int64, watchdog time.Duration) {
	for {
		last.Store(mono())
		scanDone, stopped := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(stopped)
			stopScan(ctx, a, scanDone, last, watchdog)
		}()
		err := a.Scan(cb)
		close(scanDone)
		<-stopped
		if ctx.Err() != nil {
			return
		}
		slog.Warn("blugw: scan ended, restarting", "err", err)
		// Some Linux Scan error paths leave the scan registered, which makes
		// the next Scan fail. Once Scan has returned this is a no-op elsewhere.
		_ = a.StopScan()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(restartDelay):
			}
			err := a.Enable()
			if err == nil {
				break
			}
			slog.Warn("blugw: cannot enable adapter", "err", err)
		}
	}
}

// stopScan calls a.StopScan once ctx is done or the watchdog fires, unless
// the scan ends first.
func stopScan(ctx context.Context, a *bluetooth.Adapter, scanDone <-chan struct{}, last *atomic.Int64, watchdog time.Duration) {
	for {
		var wd <-chan time.Time
		if watchdog > 0 {
			wd = time.After(watchdog - time.Duration(mono()-last.Load()))
		}
		select {
		case <-scanDone:
			return
		case <-ctx.Done():
		case <-wd:
			idle := time.Duration(mono() - last.Load())
			if idle < watchdog {
				continue
			}
			slog.Warn("blugw: no BTHome adverts, restarting scan", "idle", idle.Round(time.Second))
		}
		break
	}
	// StopScan fails until Scan has registered itself. It must succeed at
	// most once per Scan: on darwin a second call can send on a closed channel.
	// ponytail: on Linux tinygo's StopScan races with Scan ending by itself
	// (unsynchronised scanCancelChan, a double close panics); the window is
	// microseconds, fix upstream rather than here.
	for a.StopScan() != nil {
		select {
		case <-scanDone:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// advert is the part of a scan result blugw uses, copied out of the callback.
type advert struct {
	addr string // platform address: a MAC on Linux, a CoreBluetooth UUID on macOS
	name string
	rssi int16
	time time.Time
	data []byte // BTHome service data from the device-info byte on
	mfr  []byte // Shelly manufacturer data after the company ID
}

// device is what the scanner remembers about one platform address.
type device struct {
	mac         bthome.MAC // from Shelly manufacturer data; zero if unknown
	model       uint16
	name        string
	raw         []byte    // last service data
	pid         byte      // last accepted packet ID
	pidTime     time.Time // when pid was accepted; zero if never
	warnedNoKey bool
}

// scanner turns adverts into readings. It is not safe for concurrent use.
//
// ponytail: devices and counters are never pruned. Real devices keep their
// addresses, so they stay small unless something floods random addresses; add
// an age sweep if that matters.
type scanner struct {
	keys     map[bthome.MAC][]byte
	allow    func(bthome.MAC) bool
	devices  map[string]*device
	counters map[bthome.MAC]uint32 // last accepted encryption counter
}

// handle processes one advert and reports whether it is a new reading.
func (s *scanner) handle(a advert) (Reading, bool) {
	d := s.devices[a.addr]
	if d == nil {
		d = &device{}
		s.devices[a.addr] = d
	}
	if a.name != "" {
		d.name = a.name
	}
	mfrMAC, model := parseShelly(a.mfr)
	if mfrMAC != (bthome.MAC{}) {
		d.mac = mfrMAC
	}
	if model != 0 {
		d.model = model
	}
	if a.data == nil {
		return Reading{}, false
	}

	mac := d.mac
	if hw, err := net.ParseMAC(a.addr); err == nil && len(hw) == 6 {
		mac = bthome.MAC(hw)
	}
	if len(a.data) >= 7 && a.data[0]&0x02 != 0 {
		// Device-info bit 1: the MAC follows, least significant byte first.
		// Decode uses it for the nonce and Packet.MAC, so the key lookup and
		// replay state must too.
		for i := range mac {
			mac[i] = a.data[6-i]
		}
	}
	if mac == (bthome.MAC{}) {
		return Reading{}, false // macOS: the scan response carrying the MAC follows within milliseconds
	}
	if s.allow != nil && !s.allow(mac) {
		return Reading{}, false
	}

	// Shelly repeats each advert for about a second, and on Linux tinygo
	// re-sends the last service data whenever another property (RSSI,
	// manufacturer data) changes, so identical bytes are never new.
	if bytes.Equal(a.data, d.raw) {
		return Reading{}, false
	}
	d.raw = a.data

	p, err := bthome.Decode(a.data, mac, s.keys[mac])
	switch {
	case errors.Is(err, bthome.ErrNoKey):
		if !d.warnedNoKey {
			slog.Warn("blugw: dropping encrypted packets, no key configured", "mac", mac.String())
			d.warnedNoKey = true
		}
		return Reading{}, false
	case err != nil && len(p.Objects) == 0 && !errors.Is(err, bthome.ErrUnknownObject):
		// Includes ErrDecrypt. Objects are only decoded once the MIC has
		// checked out, so an unknown object, or a partial packet with
		// objects, is authentic. ErrTruncated with no objects may come from
		// the unauthenticated header.
		slog.Warn("blugw: dropping packet", "mac", mac.String(), "err", err)
		return Reading{}, false
	case len(s.keys[p.MAC]) > 0 && !p.Encrypted:
		slog.Warn("blugw: dropping unencrypted packet from a device with a key", "mac", mac.String())
		return Reading{}, false
	}

	if p.Encrypted {
		// Keyed by MAC, not address: the MAC can come from spoofable
		// manufacturer data or payload, so a replay from another address must
		// still meet the last counter.
		last, ok := s.counters[p.MAC]
		if ok && p.Counter == last {
			return Reading{}, false
		}
		if ok && p.Counter < last {
			slog.Warn("blugw: dropping packet with an encryption counter lower than the last one: possible replay attack. A battery swap may reset the device counter; restarting the process clears the stored counters",
				"mac", mac.String(), "counter", p.Counter, "last", last)
			return Reading{}, false
		}
		s.counters[p.MAC] = p.Counter
	}

	var pid byte
	hasPID := false
	for _, o := range p.Objects {
		switch o.ID {
		case 0x00:
			pid, hasPID = byte(o.Value), true
		case 0xF0:
			d.model = uint16(o.Value)
		}
	}
	if hasPID {
		// Accept a packet ID up to 63 ahead of the last one (mod 256), or
		// any packet ID once the device has been quiet for a while.
		n := pid - d.pid
		if !d.pidTime.IsZero() && a.time.Sub(d.pidTime) <= dedupWindow && (n == 0 || n > 63) {
			return Reading{}, false
		}
		d.pid, d.pidTime = pid, a.time
	}

	if err != nil {
		slog.Warn("blugw: partial packet", "mac", mac.String(), "err", err)
	}
	return Reading{Packet: p, Model: d.model, Name: d.name, RSSI: a.rssi, Time: a.time}, true
}

// parseShelly parses Shelly manufacturer data: a sequence of [type][payload]
// blocks. It stops at an unknown type, such as the 0x0D that starts a time
// beacon. Zero values mean absent.
func parseShelly(b []byte) (mac bthome.MAC, model uint16) {
	for len(b) > 0 {
		switch {
		case b[0] == 0x01 && len(b) >= 3: // flags
			b = b[3:]
		case b[0] == 0x0A && len(b) >= 7: // MAC, least significant byte first
			for i := range mac {
				mac[i] = b[6-i]
			}
			b = b[7:]
		case b[0] == 0x0B && len(b) >= 3: // model ID
			model = binary.LittleEndian.Uint16(b[1:])
			b = b[3:]
		default:
			return mac, model
		}
	}
	return mac, model
}

// timeBeacon returns the Shelly time beacon for now in loc, as manufacturer
// data after the company ID: 0x0D, then little-endian Unix time (uint32), the
// UTC offset of standard time (int32 seconds), the start and end of DST in
// the current local year (uint32 Unix times, 0 without DST) and the DST shift
// (int32 seconds).
//
// Shelly does not document the format. The DST fields are those of a POSIX
// TZ rule: both transitions fall in the current year, so in the southern
// hemisphere start is after end. A capture from a UK plug in October matches,
// but cannot tell this from "the current or next DST period"; one taken in
// November or December could.
func timeBeacon(now time.Time, loc *time.Location) []byte {
	now = now.In(loc)
	_, std := now.Zone()
	dst := std
	var start, end int64
	year := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, loc)
	next := year.AddDate(1, 0, 0)
	for t := year; t.Before(next); {
		_, off := t.Zone()
		from, to := t.ZoneBounds()
		if t.IsDST() {
			dst = off
			if !from.Before(year) {
				start = from.Unix()
			}
			if !to.IsZero() && to.Before(next) {
				end = to.Unix()
			}
		} else {
			std = off
		}
		if to.IsZero() {
			break
		}
		t = to
	}
	b := []byte{0x0D}
	b = binary.LittleEndian.AppendUint32(b, uint32(now.Unix()))
	b = binary.LittleEndian.AppendUint32(b, uint32(std))
	b = binary.LittleEndian.AppendUint32(b, uint32(start))
	b = binary.LittleEndian.AppendUint32(b, uint32(end))
	return binary.LittleEndian.AppendUint32(b, uint32(dst-std))
}
