package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/ZerkerEOD/heimdall-listener/pkg/decode"
	"github.com/ZerkerEOD/heimdall-listener/pkg/run"
)

// protocolColor returns the accent colour for a protocol, tuned for the
// active light or dark theme variant.
func protocolColor(p decode.Protocol) color.Color {
	dark := fyne.CurrentApp() != nil && fyne.CurrentApp().Settings().ThemeVariant() == theme.VariantDark
	type pair struct{ light, dark color.NRGBA }
	palette := map[decode.Protocol]pair{
		decode.ProtoLLMNR:  {color.NRGBA{0xd9, 0x53, 0x4f, 0xff}, color.NRGBA{0xff, 0x7b, 0x72, 0xff}}, // red
		decode.ProtoNBNS:   {color.NRGBA{0xe6, 0x7e, 0x22, 0xff}, color.NRGBA{0xff, 0xa6, 0x57, 0xff}}, // orange
		decode.ProtoMDNS:   {color.NRGBA{0x2e, 0x86, 0xc1, 0xff}, color.NRGBA{0x58, 0xa6, 0xff, 0xff}}, // blue
		decode.ProtoDNS:    {color.NRGBA{0x8e, 0x44, 0xad, 0xff}, color.NRGBA{0xbc, 0x8c, 0xff, 0xff}}, // purple
		decode.ProtoDHCPv6: {color.NRGBA{0x16, 0xa0, 0x85, 0xff}, color.NRGBA{0x3f, 0xb9, 0x50, 0xff}}, // teal/green
		decode.ProtoHTTP:   {color.NRGBA{0x7f, 0x8c, 0x8d, 0xff}, color.NRGBA{0x8b, 0x94, 0x9e, 0xff}}, // grey
	}
	c, ok := palette[p]
	if !ok {
		return color.Transparent
	}
	if dark {
		return c.dark
	}
	return c.light
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
