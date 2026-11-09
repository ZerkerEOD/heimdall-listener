package ui

import (
	"image/color"

	"fyne.io/fyne/v2/theme"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// protocolColor returns the accent colour for a protocol on the dark
// Heimdall theme.
func protocolColor(p decode.Protocol) color.Color {
	palette := map[decode.Protocol]color.NRGBA{
		decode.ProtoLLMNR:  {0xff, 0x4d, 0x57, 0xff}, // red
		decode.ProtoNBNS:   {0xff, 0xa6, 0x57, 0xff}, // orange
		decode.ProtoMDNS:   {0x58, 0xa6, 0xff, 0xff}, // blue
		decode.ProtoDNS:    {0xbc, 0x8c, 0xff, 0xff}, // purple
		decode.ProtoDHCPv6: {0x3f, 0xc3, 0x7a, 0xff}, // green
		decode.ProtoHTTP:   {0x9a, 0xa3, 0xad, 0xff}, // grey
	}
	if c, ok := palette[p]; ok {
		return c
	}
	return color.Transparent
}

// severityColor maps alert severities to theme colours.
func severityColor(s run.Severity) color.Color {
	switch s {
	case run.SeverityHigh:
		return theme.Color(theme.ColorNameError)
	case run.SeverityMedium:
		return theme.Color(theme.ColorNameWarning)
	case run.SeverityLow:
		return theme.Color(theme.ColorNamePrimary)
	default:
		return theme.Color(theme.ColorNamePlaceHolder)
	}
}

// statusColor maps diff statuses to theme colours.
func statusColor(s run.Status) color.Color {
	switch s {
	case run.StatusNew:
		return theme.Color(theme.ColorNameError)
	case run.StatusResolved:
		return theme.Color(theme.ColorNameSuccess)
	default:
		return color.Transparent
	}
}
