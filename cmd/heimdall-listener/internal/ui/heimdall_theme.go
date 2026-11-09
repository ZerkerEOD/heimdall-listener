package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// heimdallTheme is the application's black and red look. Surfaces are
// near-black, the accent (primary, selection, focus, tab indicator, high
// importance buttons) is crimson, and text stays high-contrast. Everything
// not listed falls back to Fyne's dark theme.
type heimdallTheme struct{}

var _ fyne.Theme = heimdallTheme{}

var heimdallColors = map[fyne.ThemeColorName]color.Color{
	theme.ColorNameBackground:          color.NRGBA{0x0c, 0x0c, 0x0e, 0xff},
	theme.ColorNameHeaderBackground:    color.NRGBA{0x16, 0x14, 0x16, 0xff},
	theme.ColorNameMenuBackground:      color.NRGBA{0x16, 0x14, 0x16, 0xff},
	theme.ColorNameOverlayBackground:   color.NRGBA{0x14, 0x12, 0x14, 0xff},
	theme.ColorNameInputBackground:     color.NRGBA{0x1a, 0x18, 0x1a, 0xff},
	theme.ColorNameInputBorder:         color.NRGBA{0x3a, 0x2a, 0x2c, 0xff},
	theme.ColorNameButton:              color.NRGBA{0x22, 0x1e, 0x20, 0xff},
	theme.ColorNameDisabledButton:      color.NRGBA{0x18, 0x16, 0x18, 0xff},
	theme.ColorNameSeparator:           color.NRGBA{0x2a, 0x24, 0x26, 0xff},
	theme.ColorNameScrollBar:           color.NRGBA{0x8a, 0x2a, 0x2e, 0xa0},
	theme.ColorNameScrollBarBackground: color.NRGBA{0x12, 0x10, 0x12, 0xff},
	theme.ColorNameShadow:              color.NRGBA{0x00, 0x00, 0x00, 0x99},

	theme.ColorNamePrimary:             color.NRGBA{0xd7, 0x1f, 0x2b, 0xff}, // crimson
	theme.ColorNameHyperlink:           color.NRGBA{0xff, 0x5a, 0x62, 0xff},
	theme.ColorNameFocus:               color.NRGBA{0xd7, 0x1f, 0x2b, 0x99},
	theme.ColorNameSelection:           color.NRGBA{0xd7, 0x1f, 0x2b, 0x55},
	theme.ColorNameHover:               color.NRGBA{0xff, 0xff, 0xff, 0x12},
	theme.ColorNamePressed:             color.NRGBA{0xd7, 0x1f, 0x2b, 0x44},
	theme.ColorNameForeground:          color.NRGBA{0xf2, 0xee, 0xee, 0xff},
	theme.ColorNameForegroundOnPrimary: color.NRGBA{0xff, 0xff, 0xff, 0xff},
	theme.ColorNamePlaceHolder:         color.NRGBA{0x8d, 0x84, 0x86, 0xff},
	theme.ColorNameDisabled:            color.NRGBA{0x5c, 0x55, 0x57, 0xff},

	// Semantic colours stay distinguishable from the crimson accent.
	theme.ColorNameError:   color.NRGBA{0xff, 0x6a, 0x3d, 0xff}, // orange-red
	theme.ColorNameWarning: color.NRGBA{0xf5, 0xb3, 0x2f, 0xff},
	theme.ColorNameSuccess: color.NRGBA{0x3f, 0xc3, 0x7a, 0xff},
}

func (heimdallTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	if c, ok := heimdallColors[name]; ok {
		return c
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (heimdallTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}
func (heimdallTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}
func (heimdallTheme) Size(name fyne.ThemeSizeName) float32 { return theme.DefaultTheme().Size(name) }
