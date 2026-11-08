package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Thin wrappers keep icon choices in one place.
func iconFolderOpen() fyne.Resource   { return theme.FolderOpenIcon() }
func iconDocumentSave() fyne.Resource { return theme.DocumentSaveIcon() }
func iconViewRefresh() fyne.Resource  { return theme.ViewRefreshIcon() }
