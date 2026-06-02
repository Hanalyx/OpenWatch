package collector

import (
	"reflect"
	"testing"
)

// Fixture mirrors the JSON `ip -j addr show` emits on a RHEL 9 box
// with one physical interface + the loopback. Loopback's MAC is
// 00:00:00:00:00:00 (we normalize to ""). The physical interface has
// both IPv4 and IPv6.
const ipAddrFixture = `[
  {
    "ifindex": 1,
    "ifname": "lo",
    "flags": ["LOOPBACK","UP","LOWER_UP"],
    "mtu": 65536,
    "qdisc": "noqueue",
    "operstate": "UNKNOWN",
    "group": "default",
    "txqlen": 1000,
    "link_type": "loopback",
    "address": "00:00:00:00:00:00",
    "broadcast": "00:00:00:00:00:00",
    "addr_info": [
      {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host", "label": "lo", "valid_life_time": 4294967295, "preferred_life_time": 4294967295},
      {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host", "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
    ]
  },
  {
    "ifindex": 2,
    "ifname": "eno1",
    "flags": ["BROADCAST","MULTICAST","UP","LOWER_UP"],
    "mtu": 1500,
    "qdisc": "fq_codel",
    "operstate": "UP",
    "group": "default",
    "txqlen": 1000,
    "link_type": "ether",
    "address": "52:54:00:a3:b8:1f",
    "broadcast": "ff:ff:ff:ff:ff:ff",
    "addr_info": [
      {"family": "inet", "local": "192.168.1.214", "prefixlen": 24, "broadcast": "192.168.1.255", "scope": "global", "dynamic": true, "label": "eno1", "valid_life_time": 86400, "preferred_life_time": 86400},
      {"family": "inet6", "local": "fe80::5054:ff:fea3:b81f", "prefixlen": 64, "scope": "link", "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
    ]
  },
  {
    "ifindex": 3,
    "ifname": "docker0",
    "flags": ["NO-CARRIER","BROADCAST","MULTICAST","UP"],
    "mtu": 1500,
    "qdisc": "noqueue",
    "operstate": "DOWN",
    "group": "default",
    "link_type": "ether",
    "address": "02:42:99:b3:5e:01",
    "addr_info": [
      {"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global", "label": "docker0", "valid_life_time": 4294967295, "preferred_life_time": 4294967295}
    ]
  }
]`

func TestParseIPAddrJSON_GoldenRHEL9(t *testing.T) {
	got, err := ParseIPAddrJSON([]byte(ipAddrFixture))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 interfaces, got %d", len(got))
	}

	// lo — loopback, MAC normalized to empty, both v4 + v6.
	lo := got[0]
	if lo.Name != "lo" || lo.Type != "loopback" || lo.State != "UNKNOWN" {
		t.Errorf("lo identity: %+v", lo)
	}
	if lo.MAC != "" {
		t.Errorf("lo MAC = %q, want empty (normalized from 00:00:00:00:00:00)", lo.MAC)
	}
	if lo.MTU != 65536 {
		t.Errorf("lo MTU = %d, want 65536", lo.MTU)
	}
	if !reflect.DeepEqual(lo.IPv4Addrs, []string{"127.0.0.1/8"}) {
		t.Errorf("lo IPv4 = %v", lo.IPv4Addrs)
	}
	if !reflect.DeepEqual(lo.IPv6Addrs, []string{"::1/128"}) {
		t.Errorf("lo IPv6 = %v", lo.IPv6Addrs)
	}

	// eno1 — physical, full set.
	eno1 := got[1]
	if eno1.Name != "eno1" || eno1.Type != "physical" || eno1.State != "UP" {
		t.Errorf("eno1 identity: %+v", eno1)
	}
	if eno1.MAC != "52:54:00:a3:b8:1f" {
		t.Errorf("eno1 MAC = %q", eno1.MAC)
	}
	if eno1.MTU != 1500 {
		t.Errorf("eno1 MTU = %d", eno1.MTU)
	}
	if !reflect.DeepEqual(eno1.IPv4Addrs, []string{"192.168.1.214/24"}) {
		t.Errorf("eno1 IPv4 = %v", eno1.IPv4Addrs)
	}
	if len(eno1.IPv6Addrs) != 1 || eno1.IPv6Addrs[0] != "fe80::5054:ff:fea3:b81f/64" {
		t.Errorf("eno1 IPv6 = %v", eno1.IPv6Addrs)
	}

	// docker0 — link_type=ether but name starts with "docker" → virtual.
	dkr := got[2]
	if dkr.Type != "virtual" {
		t.Errorf("docker0 Type = %q, want virtual", dkr.Type)
	}
	if dkr.State != "DOWN" {
		t.Errorf("docker0 State = %q, want DOWN", dkr.State)
	}
}

func TestParseIPAddrJSON_MalformedReturnsError(t *testing.T) {
	if _, err := ParseIPAddrJSON([]byte("not-json")); err == nil {
		t.Error("want error on malformed input, got nil")
	}
}

// `ip -j route show` on a host with default + connected + DHCP-supplied
// link-local routes.
const ipRouteFixture = `[
  {"dst":"default","gateway":"192.168.1.1","dev":"eno1","protocol":"dhcp","metric":100,"flags":[]},
  {"dst":"192.168.1.0/24","dev":"eno1","protocol":"kernel","scope":"link","prefsrc":"192.168.1.214","metric":100,"flags":[]},
  {"dst":"169.254.0.0/16","dev":"eno1","scope":"link","metric":1000,"flags":[]},
  {"dst":"127.0.0.0/8","dev":"lo","scope":"host","flags":[]}
]`

func TestParseIPRouteJSON_GoldenRHEL9(t *testing.T) {
	got, err := ParseIPRouteJSON([]byte(ipRouteFixture))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 routes, got %d", len(got))
	}
	// default → 192.168.1.1 via eno1
	if got[0].Destination != "default" || got[0].Gateway != "192.168.1.1" || got[0].Interface != "eno1" || got[0].Metric != 100 || got[0].Protocol != "dhcp" {
		t.Errorf("default route: %+v", got[0])
	}
	// link-local route has no Gateway, scope=link
	if got[2].Destination != "169.254.0.0/16" || got[2].Gateway != "" || got[2].Scope != "link" || got[2].Metric != 1000 {
		t.Errorf("link-local route: %+v", got[2])
	}
	// host route — metric omitted in JSON → 0
	if got[3].Destination != "127.0.0.0/8" || got[3].Metric != 0 || got[3].Scope != "host" {
		t.Errorf("host route: %+v", got[3])
	}
}

func TestParseSysfsNetStats_PipeDelimitedRows(t *testing.T) {
	input := []byte(`eno1|1000|full|virtio_net|45123456789|5234567890
lo|||||0|0
docker0|-1||bridge|123|456
`)
	got := ParseSysfsNetStats(input)
	if len(got) != 3 {
		t.Fatalf("want 3 rows, got %d (%v)", len(got), got)
	}
	if eno1 := got["eno1"]; eno1.SpeedMbps != 1000 || eno1.Duplex != "full" || eno1.Driver != "virtio_net" || eno1.RxBytes != 45123456789 || eno1.TxBytes != 5234567890 {
		t.Errorf("eno1 stats: %+v", eno1)
	}
	// loopback — everything empty/zero
	if lo := got["lo"]; lo.SpeedMbps != 0 || lo.Driver != "" || lo.Duplex != "" {
		t.Errorf("lo stats: %+v", lo)
	}
	// docker0 — speed=-1 normalized to 0
	if dkr := got["docker0"]; dkr.SpeedMbps != 0 {
		t.Errorf("docker0 SpeedMbps = %d, want 0 (kernel reports -1)", dkr.SpeedMbps)
	}
}

func TestParseSysfsNetStats_SkipsMalformedLines(t *testing.T) {
	input := []byte(`eno1|1000|full|virtio_net|1|2
short|line
||||||
lo|||||0|0
`)
	got := ParseSysfsNetStats(input)
	// short line dropped (< 6 fields); blank-name row tolerated; lo + eno1 kept.
	if _, ok := got["eno1"]; !ok {
		t.Error("eno1 missing")
	}
	if _, ok := got["lo"]; !ok {
		t.Error("lo missing")
	}
	if _, ok := got["short"]; ok {
		t.Error("short line should have been dropped")
	}
}

func TestMergeNetworkInterfaces_FoldsSysfsIntoIPAddrOutput(t *testing.T) {
	base := []NetworkInterface{
		{Name: "eno1", Type: "physical", State: "UP", MAC: "52:54:00:a3:b8:1f", MTU: 1500},
		{Name: "lo", Type: "loopback", State: "UNKNOWN", MTU: 65536},
	}
	stats := map[string]sysfsStats{
		"eno1": {Driver: "virtio_net", SpeedMbps: 1000, Duplex: "full", RxBytes: 42_100_000_000, TxBytes: 4_800_000_000},
		"lo":   {RxBytes: 999, TxBytes: 999},
	}
	got := MergeNetworkInterfaces(base, stats)
	if got[0].Driver != "virtio_net" || got[0].SpeedMbps != 1000 || got[0].Duplex != "full" {
		t.Errorf("eno1 merged: %+v", got[0])
	}
	if got[0].RxBytes != 42_100_000_000 || got[0].TxBytes != 4_800_000_000 {
		t.Errorf("eno1 RX/TX: %d/%d", got[0].RxBytes, got[0].TxBytes)
	}
	if got[1].Driver != "" || got[1].SpeedMbps != 0 {
		t.Errorf("lo should have no driver/speed: %+v", got[1])
	}
	// Source slice untouched.
	if base[0].Driver != "" {
		t.Error("Merge mutated input slice")
	}
}

func TestInferLinkType_HeuristicCases(t *testing.T) {
	cases := []struct {
		name, linkType, want string
	}{
		{"lo", "loopback", "loopback"},
		{"eno1", "ether", "physical"},
		{"eth0", "ether", "physical"},
		{"docker0", "ether", "virtual"},
		{"veth1234", "ether", "virtual"},
		{"br-abcdef", "ether", "virtual"},
		{"virbr0", "ether", "virtual"},
		{"tun0", "ether", "virtual"},
		{"wg0", "none", "virtual"},
	}
	for _, c := range cases {
		if got := inferLinkType(c.name, c.linkType); got != c.want {
			t.Errorf("inferLinkType(%q, %q) = %q, want %q", c.name, c.linkType, got, c.want)
		}
	}
}
