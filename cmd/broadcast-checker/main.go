package main

import (
	"broadcast-checker/pkg/listener"
	"image/color"
	"log"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/google/gopacket/pcap"
)

type myDarkTheme struct{}

func (m myDarkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (m myDarkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (m myDarkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (m myDarkTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameText {
		return 10
	}
	return theme.DefaultTheme().Size(name)
}

func getInternetInterfaces() ([]pcap.Interface, error) {
	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var internetInterfaces []pcap.Interface
	for _, iface := range allInterfaces {
		if hasInternetAddress(iface) {
			internetInterfaces = append(internetInterfaces, iface)
		}
	}
	return internetInterfaces, nil
}

func hasInternetAddress(iface pcap.Interface) bool {
	for _, addr := range iface.Addresses {
		ip := addr.IP
		if ip.To4() != nil || ip.To16() != nil {
			if !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
				return true
			}
		}
	}
	return false
}

// Define a struct to hold unique capture information
type CaptureInfo struct {
	IP       string
	Protocol string
	Hostname string
	IsWPAD   bool
}

// Modify the main function and add these new functions
func main() {
	myApp := app.New()
	myApp.Settings().SetTheme(&myDarkTheme{})
	myWindow := myApp.NewWindow("Broadcast Checker")

	// Initialize listener
	listener.Init()

	// Display the elevated privileges warning
	warning := listener.CheckElevatedPrivileges()
	dialog.ShowInformation("Privilege Warning", warning, myWindow)

	// Get available internet interfaces
	interfaces, err := getInternetInterfaces()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	// Create a slice to store the data
	var captures []CaptureInfo

	// Create the table
	table := widget.NewTable(
		func() (int, int) { return len(captures), 3 },
		func() fyne.CanvasObject {
			return widget.NewLabel("wide content")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)
			label.Truncation = fyne.TextTruncateClip

			if id.Row == 0 {
				// Header row
				switch id.Col {
				case 0:
					label.SetText("Source IP")
				case 1:
					label.SetText("Protocol")
				case 2:
					label.SetText("Requested Hostname")
				}
				label.TextStyle = fyne.TextStyle{Bold: true}
			} else if id.Row <= len(captures) {
				capture := captures[id.Row-1]
				switch id.Col {
				case 0:
					label.SetText(capture.IP)
				case 1:
					label.SetText(capture.Protocol)
				case 2:
					label.SetText(capture.Hostname)
				}
			}
		},
	)

	// Set column widths
	table.SetColumnWidth(0, 120) // Source IP
	table.SetColumnWidth(1, 80)  // Protocol
	table.SetColumnWidth(2, 200) // Requested Hostname

	// Create protocol selector
	protocolSelector := widget.NewSelect([]string{"All", "LLMNR", "NetBIOS", "mDNS", "WPAD"}, func(selected string) {
		updateTable(captures, selected, table)
	})
	protocolSelector.SetSelected("All")

	// Create interface dropdown
	var selectedInterface string
	interfaceNames := make([]string, len(interfaces))
	for i, iface := range interfaces {
		interfaceNames[i] = iface.Name
	}
	interfaceSelect := widget.NewSelect(interfaceNames, func(value string) {
		selectedInterface = value
	})
	if len(interfaceNames) > 0 {
		interfaceSelect.SetSelected(interfaceNames[0])
	}

	// Create the listen button
	var listenButton *widget.Button
	listenButton = widget.NewButton("Start Listening", func() {
		if listenButton.Text == "Start Listening" {
			go listener.StartListening(selectedInterface)
			listenButton.SetText("Stop Listening")
		} else {
			listener.StopListening()
			listenButton.SetText("Start Listening")
		}
	})

	// Create the layout
	controls := container.NewHBox(interfaceSelect, listenButton, protocolSelector)
	content := container.NewBorder(
		controls,
		nil,
		nil,
		nil,
		table,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(600, 400))

	// Start a goroutine to update the table
	go func() {
		for newData := range listener.DataChannel {
			addCapture(&captures, newData.SourceIP, newData.Protocol, newData.RequestedHostname)
			updateTable(captures, protocolSelector.Selected, table)
		}
	}()

	myWindow.ShowAndRun()
}

// Implement the addCapture function
func addCapture(captures *[]CaptureInfo, ip, protocol, hostname string) {
	isWPAD := strings.ToLower(hostname) == "wpad"
	*captures = append(*captures, CaptureInfo{
		IP:       ip,
		Protocol: protocol,
		Hostname: hostname,
		IsWPAD:   isWPAD,
	})

	// Add a separate WPAD entry if the hostname is "wpad"
	if isWPAD {
		*captures = append(*captures, CaptureInfo{
			IP:       ip,
			Protocol: "WPAD",
			Hostname: hostname,
			IsWPAD:   true,
		})
	}
}

// Implement the updateTable function
func updateTable(captures []CaptureInfo, selectedProtocol string, table *widget.Table) {
	filteredCaptures := filter(captures, func(c CaptureInfo) bool {
		return selectedProtocol == "All" ||
			c.Protocol == selectedProtocol ||
			(selectedProtocol == "WPAD" && c.IsWPAD)
	})

	table.Length = func() (int, int) {
		return len(filteredCaptures) + 1, 3 // +1 for header row
	}

	table.UpdateCell = func(id widget.TableCellID, cell fyne.CanvasObject) {
		label := cell.(*widget.Label)
		label.Truncation = fyne.TextTruncateClip

		if id.Row == 0 {
			// Header row
			switch id.Col {
			case 0:
				label.SetText("Source IP")
			case 1:
				label.SetText("Protocol")
			case 2:
				label.SetText("Requested Hostname")
			}
			label.TextStyle = fyne.TextStyle{Bold: true}
		} else if id.Row <= len(filteredCaptures) {
			capture := filteredCaptures[id.Row-1]
			switch id.Col {
			case 0:
				label.SetText(capture.IP)
			case 1:
				label.SetText(capture.Protocol)
			case 2:
				label.SetText(capture.Hostname)
			}
		}
	}

	table.Refresh()
}

// Update the filter function
func filter(captures []CaptureInfo, predicate func(CaptureInfo) bool) []CaptureInfo {
	result := []CaptureInfo{}
	for _, capture := range captures {
		if predicate(capture) {
			result = append(result, capture)
		}
	}
	return result
}
