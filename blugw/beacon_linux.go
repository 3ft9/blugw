package blugw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
	"golang.org/x/sys/unix"
)

const (
	beaconPath     = dbus.ObjectPath("/blugw/timebeacon")
	beaconInterval = 4 * time.Second // as often as Shelly plugs send theirs
)

var errUnsynced = errors.New("system clock is not NTP-synchronised")

// beacon broadcasts the Shelly time beacon until ctx is done, refreshing its
// timestamp every beaconInterval. Devices take the time as their encryption
// counter, so it broadcasts only while the clock is synchronised: a wrong
// time would make every receiver reject them.
func beacon(ctx context.Context) {
	t := time.NewTicker(beaconInterval)
	defer t.Stop()
	logged := ""
	for {
		err := errUnsynced
		if clockSynced() {
			err = advertise(timeBeacon(time.Now(), time.Local))
		} else {
			_ = advertise(nil)
		}
		if s := fmt.Sprint(err); s != logged {
			if err != nil {
				slog.Warn("blugw: time beacon off", "err", err)
			} else {
				slog.Info("blugw: time beacon on")
			}
			logged = s
		}
		select {
		case <-ctx.Done():
			_ = advertise(nil)
			return
		case <-t.C:
		}
	}
}

// advertise unregisters the beacon from BlueZ and, unless payload is nil,
// registers it again carrying payload. It bypasses tinygo, whose
// Advertisement cannot change its data: every Configure exports a new D-Bus
// object that is never removed, and every Start makes the adapter
// discoverable. Exporting at a fixed path replaces the previous object.
func advertise(payload []byte) error {
	conn, err := dbus.SystemBus() // shared with tinygo
	if err != nil {
		return err
	}
	adapter := conn.Object("org.bluez", "/org/bluez/hci0") // bluetooth.DefaultAdapter
	// Fails harmlessly when not registered, as after bluetoothd restarts.
	adapter.Call("org.bluez.LEAdvertisingManager1.UnregisterAdvertisement", 0, beaconPath)
	if payload == nil {
		return nil
	}
	_, err = prop.Export(conn, beaconPath, prop.Map{"org.bluez.LEAdvertisement1": {
		"Type":             {Value: "broadcast"},
		"ManufacturerData": {Value: map[uint16]any{shellyCompany: payload}},
		// BlueZ drops the advertisement by itself if we stop refreshing it,
		// as when the process is paused, so a stale time is not left on air.
		"Timeout": {Value: uint16(3 * beaconInterval / time.Second)},
	}})
	if err != nil {
		return err
	}
	return adapter.Call("org.bluez.LEAdvertisingManager1.RegisterAdvertisement", 0, beaconPath, map[string]any{}).Err
}

// clockSynced reports whether the system clock is synchronised, by the test
// timedatectl uses: the kernel's maximum error is under 16 s. NTP clients
// lower it, the kernel raises it by 0.5 ms a second, and setting the clock
// resets it to 16 s. STA_UNSYNC is no use: chrony clears it only with rtcsync.
func clockSynced() bool {
	var tx unix.Timex // Modes 0: read only
	_, err := unix.Adjtimex(&tx)
	return err == nil && tx.Maxerror < 16_000_000 // µs
}
