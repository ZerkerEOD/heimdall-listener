package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// cell is the template object for table cells: a thin colour accent on the
// leading edge plus an ellipsis-truncated label.
type cell struct {
	widget.BaseWidget
	accent *canvas.Rectangle
	label  *widget.Label
	box    *fyne.Container
}

func newCell() *cell {
	c := &cell{accent: canvas.NewRectangle(color.Transparent), label: widget.NewLabel("")}
	c.accent.SetMinSize(fyne.NewSize(4, 1))
	c.label.Truncation = fyne.TextTruncateEllipsis
	c.box = container.NewBorder(nil, nil, c.accent, nil, c.label)
	c.ExtendBaseWidget(c)
	return c
}

func (c *cell) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(c.box)
}

// set updates text, boldness and accent colour in one go.
func (c *cell) set(text string, bold bool, accent color.Color) {
	c.label.TextStyle = fyne.TextStyle{Bold: bold}
	c.label.SetText(text)
	c.accent.FillColor = accent
	c.accent.Refresh()
}

// headerButton builds a clickable, left-aligned header cell.
func headerButton() *widget.Button {
	b := widget.NewButton("", nil)
	b.Importance = widget.LowImportance
	b.Alignment = widget.ButtonAlignLeading
	return b
}
