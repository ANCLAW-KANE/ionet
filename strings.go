package main

import (
	"fmt"
	"strings"
)

var views = []string{"raw", "agg"}

const format_row = "%-8s%s%-8s%s%-3s%s%8s%s %-45s %s %-45s %s%-12s%s%-10s%s%-9s"
const format_agg = "%-45s%s%-5s%s%-8s%s%-8s%s%12s%s%12s%s%12s%s%30s"

const maxRows = 3000
const (
	DIRECTION_INGRESS = "🠃🠃🠃"
	DIRECTION_EGRESS  = "🠑🠑🠑"
)
const (
	PKT_TYPE_HOST      = "HOST"
	PKT_TYPE_BROADCAST = "BROADCAST"
	PKT_TYPE_MULTICAST = "MULTICAST"
	PKT_TYPE_OTHERHOST = "OTHERHOST"
	PKT_TYPE_OUTGOING  = "OUTGOING"
	PKT_TYPE_LOOPBACK  = "LOOPBACK"
	PKT_TYPE_FASTROUTE = "FASTROUTE"
)

const (
	KB = 1 << 10
	MB = 1 << 20
	GB = 1 << 30
	TB = 1 << 40
	PB = 1 << 50
)

const (
	IP_TYPE_V4_LOCAL    = "v4Local"
	IP_TYPE_V4_EXTERNAL = "v4External"

	IP_TYPE_V6_LOCAL    = "v6Local"
	IP_TYPE_V6_EXTERNAL = "v6External"
)

const (
	packetsCountWidth = 8
	portWidth         = 5
	dnsNameWidth      = 30
	ipWidth           = 45

	timeWidth    = 8
	protoWidth   = 8
	dirWidth     = 3
	ifWidth      = 8
	srcWidth     = 45
	dstWidth     = 45
	bytesWidth   = 12
	typeWidth    = 10
	pktTypeWidth = 9
)

var tableHeader = fmt.Sprintf(
	format_row,
	"Time", coloredSeparator,
	"Proto", coloredSeparator,
	"Dir", coloredSeparator,
	"IF", coloredSeparator,
	"Source", coloredSeparator,
	"Destination", coloredSeparator,
	"Bytes", coloredSeparator,
	"Type", coloredSeparator,
	"Pkttype",
)

var tableHeaderAgg = fmt.Sprintf(
	format_agg,
	"IP", coloredSeparator,
	"PORT", coloredSeparator,
	"PROTOCOL", coloredSeparator,
	"COUNT", coloredSeparator,
	"INGRESS", coloredSeparator,
	"EGRESS", coloredSeparator,
	"TOTAL", coloredSeparator,
	"DNS_NAME",
)

var separator_agg = strings.Join([]string{
	strings.Repeat(coloredLine, ipWidth),
	coloredCross,
	strings.Repeat(coloredLine, portWidth),
	coloredCross,
	strings.Repeat(coloredLine, protoWidth),
	coloredCross,
	strings.Repeat(coloredLine, packetsCountWidth),
	coloredCross,
	strings.Repeat(coloredLine, bytesWidth),
	coloredCross,
	strings.Repeat(coloredLine, bytesWidth),
	coloredCross,
	strings.Repeat(coloredLine, bytesWidth),
	coloredCross,
	strings.Repeat(coloredLine, dnsNameWidth),
}, "")

var separator = strings.Join([]string{
	strings.Repeat(coloredLine, timeWidth),
	coloredCross,
	strings.Repeat(coloredLine, protoWidth),
	coloredCross,
	strings.Repeat(coloredLine, dirWidth),
	coloredCross,
	strings.Repeat(coloredLine, ifWidth),
	coloredCross,
	strings.Repeat(coloredLine, srcWidth+2), //+padding
	coloredCross,
	strings.Repeat(coloredLine, dstWidth+2),
	coloredCross,
	strings.Repeat(coloredLine, bytesWidth),
	coloredCross,
	strings.Repeat(coloredLine, typeWidth),
	coloredCross,
	strings.Repeat(coloredLine, pktTypeWidth),
}, "")

const ERR_CHAN = "full_chan"
