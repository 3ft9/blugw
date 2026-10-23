package main

import (
	"cmp"
	"encoding/hex"
	"strings"

	"github.com/3ft9/blugw/bthome"
)

// shellyModels names Shelly BLU model IDs, from manufacturer data or object 0xF0.
var shellyModels = map[uint16]string{
	0x0001: "BLU Button1",
	0x0002: "BLU Door/Window",
	0x0003: "BLU H&T",
	0x0004: "BLU Distance",
	0x0005: "BLU Motion",
	0x0006: "BLU Wall Switch 4",
	0x0007: "BLU RC Button 4",
	0x0008: "BLU TRV",
	0x0009: "BLU Remote Control ZB",
	0x000B: "BLU Weather Station",
	0x000C: "BLU H&T Display ZB",
	0x0011: "BLU H&T ZB",
	0x0013: "BLU Motion ZB",
	0x0014: "BLU Door/Window ZB",
	0x0015: "BLU Wall Switch 4 ZB",
	0x0016: "BLU RC Button 4 ZB",
	0x0017: "BLU Button Tough 1 ZB",
	0x0020: "BLU Door/Window Mini ZB",
	0x0021: "BLU Door/Window Outdoor ZB",
}

// sensorClasses maps object names to a Home Assistant sensor device class and
// state class. Every BTHome unit for these names is in the device class's
// allowed units; HA's MQTT sensor maps the micro sign µ to μ itself. Volume
// does not allow the measurement state class.
var sensorClasses = map[string][2]string{
	"battery":          {"battery", "measurement"},
	"co2":              {"carbon_dioxide", "measurement"},
	"conductivity":     {"conductivity", "measurement"},
	"current":          {"current", "measurement"},
	"dewpoint":         {"temperature", "measurement"},
	"distance":         {"distance", "measurement"},
	"duration":         {"duration", "measurement"},
	"energy":           {"energy", "total_increasing"},
	"gas":              {"gas", "total_increasing"},
	"humidity":         {"humidity", "measurement"},
	"illuminance":      {"illuminance", "measurement"},
	"mass":             {"weight", "measurement"},
	"moisture":         {"moisture", "measurement"},
	"pm10":             {"pm10", "measurement"},
	"pm25":             {"pm25", "measurement"},
	"power":            {"power", "measurement"},
	"precipitation":    {"precipitation", "measurement"},
	"pressure":         {"pressure", "measurement"},
	"speed":            {"speed", "measurement"},
	"temperature":      {"temperature", "measurement"},
	"tvoc":             {"volatile_organic_compounds", "measurement"},
	"voltage":          {"voltage", "measurement"},
	"volume":           {"volume", "total"},
	"volume_flow_rate": {"volume_flow_rate", "measurement"},
	"volume_storage":   {"volume_storage", "measurement"},
	"water":            {"water", "total_increasing"},
}

// binaryClasses holds the binary sensor names whose Home Assistant device
// class is not the name itself.
var binaryClasses = map[string]string{
	"battery_low":       "battery",
	"gas_detected":      "gas",
	"generic_boolean":   "",
	"moisture_detected": "moisture",
	"power_on":          "power",
}

var eventTypes = map[byte][]string{
	0x3A: {"press", "double_press", "triple_press", "long_press", "long_double_press", "long_triple_press", "hold_press"},
	0x3B: {"off", "on", "toggle", "step_up", "step_down"},
	0x3C: {"rotate_left", "rotate_right"},
}

// discovery returns the Home Assistant device discovery config for d.
func (g *gateway) discovery(mac bthome.MAC, d *device) []byte {
	m := hex.EncodeToString(mac[:])
	cmps := map[string]any{
		m + "_rssi": map[string]any{
			"platform":            "sensor",
			"unique_id":           "blugw_" + m + "_rssi",
			"name":                title("rssi"),
			"device_class":        "signal_strength",
			"state_class":         "measurement",
			"unit_of_measurement": "dBm",
			"entity_category":     "diagnostic",
			"value_template":      "{{ value_json.rssi }}",
		},
	}
	for k, o := range d.objs {
		cmps[m+"_"+k] = g.component(m, k, o)
	}

	model := shellyModels[d.model]
	dev := map[string]any{
		"identifiers": []string{"blugw_" + m},
		"name":        cmp.Or(model, d.name, "BTHome") + " " + strings.ToUpper(m[8:]),
		"connections": [][]string{{"bluetooth", strings.ToLower(mac.String())}},
	}
	if model != "" {
		dev["manufacturer"] = "Shelly"
		dev["model"] = model
	}
	if d.name != "" {
		dev["model_id"] = d.name
	}
	if d.firmware != "" {
		dev["sw_version"] = d.firmware
	}
	return marshal(map[string]any{
		"device":             dev,
		"origin":             map[string]any{"name": "blugw-mqtt", "support_url": "https://github.com/3ft9/blugw"},
		"state_topic":        g.prefix + "/" + m,
		"availability_topic": g.status(),
		"qos":                1,
		"components":         cmps,
	})
}

// component returns the discovery config of the entity for state key k.
func (g *gateway) component(m, k string, o bthome.Object) map[string]any {
	c := map[string]any{
		"unique_id": "blugw_" + m + "_" + k,
		"name":      title(k),
	}
	switch {
	case isEvent(o):
		c["platform"] = "event"
		c["state_topic"] = g.prefix + "/" + m + "/event/" + k
		c["event_types"] = eventTypes[o.ID]
		if o.ID == 0x3A {
			c["device_class"] = "button"
		}
	case o.Binary():
		c["platform"] = "binary_sensor"
		class, ok := binaryClasses[o.Name()]
		if !ok {
			class = o.Name()
		}
		if class != "" {
			c["device_class"] = class
		}
		on, off := "ON", "OFF"
		if o.ID == 0x28 { // BTHome safety 1 means safe; HA safety on means unsafe
			on, off = off, on
		}
		c["value_template"] = ifDefined(k, "'"+on+"' if value_json."+k+" else '"+off+"'")
	default:
		c["platform"] = "sensor"
		c["value_template"] = ifDefined(k, "value_json."+k)
		if u := o.Unit(); u != "" {
			c["unit_of_measurement"] = u
		}
		if sc, ok := sensorClasses[o.Name()]; ok {
			c["device_class"], c["state_class"] = sc[0], sc[1]
		}
		if o.ID == 0x00 {
			c["entity_category"] = "diagnostic"
		}
	}
	return c
}

// ifDefined returns a template rendering expr, or nothing while the state lacks
// key k, as it does after a gateway restart until k is seen again. Binary
// sensors and sensors with a unit, state class or device class ignore empty
// output and keep their last state.
func ifDefined(k, expr string) string {
	return "{% if value_json." + k + " is defined %}{{ " + expr + " }}{% endif %}"
}

// title turns a state key into an entity name: "temperature_2" becomes
// "Temperature 2".
func title(k string) string {
	words := strings.Split(k, "_")
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	return strings.Join(words, " ")
}
