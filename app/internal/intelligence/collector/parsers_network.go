package collector

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParseIPAddrJSON parses the JSON output of `ip -j addr show` into a
// slice of NetworkInterface. Each entry comes back with name, state
// (operstate), MAC, MTU, and the IPv4/IPv6 CIDR strings observed on
// that link. Type is inferred from link_type:
//
//	loopback        -> loopback
//	ether on lo*    -> loopback (safety net)
//	ether otherwise -> physical
//	other tokens    -> "virtual"
//
// Driver / Speed / Duplex / RX / TX are NOT in `ip -j addr` output —
// they live in /sys/class/net and arrive via ParseSysfsNetStats. The
// merge happens in Merge.
func ParseIPAddrJSON(b []byte) ([]NetworkInterface, error) {
	var raw []struct {
		IfName    string   `json:"ifname"`
		Flags     []string `json:"flags"`
		Mtu       int      `json:"mtu"`
		Operstate string   `json:"operstate"`
		LinkType  string   `json:"link_type"`
		Address   string   `json:"address"`
		AddrInfo  []struct {
			Family    string `json:"family"`
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("ParseIPAddrJSON: %w", err)
	}
	out := make([]NetworkInterface, 0, len(raw))
	for _, r := range raw {
		ni := NetworkInterface{
			Name:  r.IfName,
			State: r.Operstate,
			Type:  inferLinkType(r.IfName, r.LinkType),
			MAC:   r.Address,
			MTU:   r.Mtu,
		}
		// Loopback's MAC is 00:00:00:00:00:00 — render as empty to
		// match the prototype.
		if ni.MAC == "00:00:00:00:00:00" {
			ni.MAC = ""
		}
		for _, a := range r.AddrInfo {
			cidr := a.Local + "/" + strconv.Itoa(a.Prefixlen)
			switch a.Family {
			case "inet":
				ni.IPv4Addrs = append(ni.IPv4Addrs, cidr)
			case "inet6":
				ni.IPv6Addrs = append(ni.IPv6Addrs, cidr)
			}
		}
		out = append(out, ni)
	}
	return out, nil
}

// ParseIPRouteJSON parses `ip -j route show` into a slice of Route.
// "default" routes come through with Destination="default"; CIDRs as
// strings. Metric defaults to 0 when omitted.
func ParseIPRouteJSON(b []byte) ([]Route, error) {
	var raw []struct {
		Dst      string `json:"dst"`
		Gateway  string `json:"gateway"`
		Dev      string `json:"dev"`
		Metric   int    `json:"metric"`
		Protocol string `json:"protocol"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("ParseIPRouteJSON: %w", err)
	}
	out := make([]Route, 0, len(raw))
	for _, r := range raw {
		out = append(out, Route{
			Destination: r.Dst,
			Gateway:     r.Gateway,
			Interface:   r.Dev,
			Metric:      r.Metric,
			Protocol:    r.Protocol,
			Scope:       r.Scope,
		})
	}
	return out, nil
}

// sysfsStats is the per-interface fact set sourced from
// /sys/class/net/<if>/{statistics,speed,duplex,device/driver/<basename>}.
// Internal to the package — the public surface is the merged
// []NetworkInterface.
type sysfsStats struct {
	Driver    string
	SpeedMbps int
	Duplex    string
	RxBytes   uint64
	TxBytes   uint64
}

// ParseSysfsNetStats parses the pipe-delimited output of the sysfs
// probe shell snippet (see collector.go). One line per interface:
//
//	name|speed|duplex|driver|rx_bytes|tx_bytes
//
// All fields after Name are tolerant: empty / non-numeric values turn
// into zero / empty rather than parse errors. Real-world examples:
//
//	eno1|1000|full|virtio_net|45123456789|5234567890
//	lo|||||0|0
func ParseSysfsNetStats(b []byte) map[string]sysfsStats {
	out := map[string]sysfsStats{}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}
		s := sysfsStats{
			Driver:    parts[3],
			Duplex:    parts[2],
			SpeedMbps: atoiOrZero(parts[1]),
			RxBytes:   atou64OrZero(parts[4]),
			TxBytes:   atou64OrZero(parts[5]),
		}
		// Kernel reports speed=-1 for interfaces without a phy (loopback,
		// virtual). Treat as unknown.
		if s.SpeedMbps < 0 {
			s.SpeedMbps = 0
		}
		out[parts[0]] = s
	}
	return out
}

// MergeNetworkInterfaces folds sysfs stats into the list parsed from
// `ip -j addr`. Returns a new slice; does not mutate.
func MergeNetworkInterfaces(ifaces []NetworkInterface, stats map[string]sysfsStats) []NetworkInterface {
	out := make([]NetworkInterface, len(ifaces))
	for i, ni := range ifaces {
		if s, ok := stats[ni.Name]; ok {
			ni.Driver = s.Driver
			ni.SpeedMbps = s.SpeedMbps
			ni.Duplex = s.Duplex
			ni.RxBytes = s.RxBytes
			ni.TxBytes = s.TxBytes
		}
		out[i] = ni
	}
	return out
}

// inferLinkType maps ip-link's `link_type` token + ifname onto the
// coarse Type bucket the frontend renders ("physical" / "loopback" /
// "virtual"). The frontend's stat row counts physical vs loopback so
// the bucketing is the contract; finer classification (bond, bridge,
// vlan) is BACKLOG.
func inferLinkType(name, linkType string) string {
	switch linkType {
	case "loopback":
		return "loopback"
	case "ether":
		// Heuristic: names starting with veth/docker/br-/virbr/cni are
		// virtual even though their link_type is ether.
		switch {
		case strings.HasPrefix(name, "veth"),
			strings.HasPrefix(name, "docker"),
			strings.HasPrefix(name, "br-"),
			strings.HasPrefix(name, "virbr"),
			strings.HasPrefix(name, "cni"),
			strings.HasPrefix(name, "tap"),
			strings.HasPrefix(name, "tun"):
			return "virtual"
		}
		return "physical"
	}
	return "virtual"
}

func atoiOrZero(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func atou64OrZero(s string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
