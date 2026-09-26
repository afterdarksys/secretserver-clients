package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/secretserver-go/secretserver"
	"github.com/afterdarktech/sekretsauce/pkg/keychain"
	"github.com/afterdarktech/sekretsauce/pkg/secrets"
)

// ExtractorUI manages the local credentials extractor
type ExtractorUI struct {
	app     *App
	Content fyne.CanvasObject
	list    *widget.List
	items   []extractedItem
	details *fyne.Container
}

type extractedItem struct {
	Source      string            // "Keychain" or "File"
	Name        string            // e.g file path or label
	Description string            // e.g match context or account definition
	Data        map[string]string // e.g username/password, or secret value
}

// NewExtractorUI creates the extractor UI
func NewExtractorUI(app *App) *ExtractorUI {
	e := &ExtractorUI{
		app:   app,
		items: []extractedItem{},
	}

	e.list = widget.NewList(
		func() int { return len(e.items) },
		func() fyne.CanvasObject {
			return widget.NewLabel("Template Label - Placeholder Text For Loading")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(fmt.Sprintf("[%s] %s", e.items[i].Source, e.items[i].Name))
		},
	)

	e.list.OnSelected = func(id widget.ListItemID) {
		e.showDetails(e.items[id])
	}

	e.details = container.NewVBox(widget.NewLabel("Click 'Scan System' to find unmanaged secrets"))

	scanBtn := widget.NewButton("Scan System", func() {
		e.runScan()
	})

	toolbar := container.NewHBox(scanBtn, layout.NewSpacer())

	left := container.NewBorder(toolbar, nil, nil, nil, e.list)
	split := container.NewHSplit(left, container.NewScroll(e.details))
	split.Offset = 0.3

	e.Content = container.NewPadded(split)

	return e
}

func (e *ExtractorUI) runScan() {
	e.items = []extractedItem{}
	e.list.Refresh()
	e.details.Objects = []fyne.CanvasObject{widget.NewLabel("Scanning... Please wait.")}
	e.details.Refresh()

	// Use goroutine to avoid freezing UI
	go func() {
		var newItems []extractedItem

		// 1. Scan Keychain
		kcResult, err := keychain.Scan(keychain.ScanOptions{})
		if err == nil {
			for _, item := range kcResult.Items {
				if item.Service != "" {
					newItems = append(newItems, extractedItem{
						Source:      "Keychain (" + item.ItemClass + ")",
						Name:        item.Service,
						Description: fmt.Sprintf("Account: %s\nLabel: %s", item.Account, item.Label),
						Data: map[string]string{
							"username": item.Account,
							"metadata": "Extracted from Keychain. Values omitted in dump.",
						},
					})
				}
			}
		}

		// 2. Scan Home Directory for files
		fileResult, err := secrets.ScanHomeDirectory()
		if err == nil {
			for _, s := range fileResult.SecretsFound {
				newItems = append(newItems, extractedItem{
					Source:      "File (" + s.Type + ")",
					Name:        s.File,
					Description: fmt.Sprintf("Found at line %d (Severity: %s)\nMatch Context: %s", s.Line, s.Severity, s.Context),
					Data: map[string]string{
						"match": s.Match,
						"type":  s.Type,
					},
				})
			}
		}

		e.items = newItems
		e.list.Refresh()
		e.details.Objects = []fyne.CanvasObject{widget.NewLabel(fmt.Sprintf("Scan complete. Found %d items.", len(e.items)))}
		e.details.Refresh()
	}()
}

func (e *ExtractorUI) showDetails(item extractedItem) {
	title := widget.NewLabelWithStyle(item.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	source := widget.NewLabel(fmt.Sprintf("Source: %s", item.Source))
	desc := widget.NewLabel(item.Description)

	dataStr := ""
	for k, v := range item.Data {
		dataStr += fmt.Sprintf("%s: %s\n", k, v)
	}
	dataLabel := widget.NewLabel(dataStr)

	importBtn := widget.NewButton("Import to SecretServer", func() {
		e.importSecret(item)
	})

	actions := container.NewHBox(importBtn)

	e.details.Objects = []fyne.CanvasObject{
		title,
		source,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Description:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		desc,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Data:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		dataLabel,
		widget.NewSeparator(),
		actions,
	}
	e.details.Refresh()
}

// secretNameFor maps an extracted item name onto the server's name pattern
// ^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$: other characters become '-', leading
// non-alphanumerics are trimmed and the result is capped at 255 bytes.
func secretNameFor(itemName string) string {
	var b strings.Builder
	for _, r := range "Extracted-" + itemName {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.TrimLeftFunc(b.String(), func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	if len(name) > 255 {
		name = name[:255]
	}
	return name
}

func (e *ExtractorUI) importSecret(item extractedItem) {
	if e.app.Client == nil {
		dialog.ShowError(fmt.Errorf("SecretServer client not configured"), e.app.MainWindow)
		return
	}

	dialog.ShowConfirm("Import Secret", fmt.Sprintf("Import '%s' to SecretServer?", item.Name), func(b bool) {
		if !b {
			return
		}

		name := secretNameFor(item.Name)
		req := &secretserver.SecretCreateRequest{
			Name:        name,
			Description: fmt.Sprintf("Extracted from %s\n%s", item.Source, item.Description),
			Data:        item.Data,
			Tags:        []string{"extracted", item.Source},
		}

		_, err := e.app.Client.Secrets.Create(context.Background(), req)
		var apiErr *secretserver.ErrorResponse
		if errors.As(err, &apiErr) && apiErr.Response != nil && apiErr.Response.StatusCode == http.StatusConflict {
			dialog.ShowError(fmt.Errorf("a secret named %q already exists; rename or delete it before importing", name), e.app.MainWindow)
			return
		}
		if err != nil {
			dialog.ShowError(err, e.app.MainWindow)
			return
		}

		dialog.ShowInformation("Success", "Secret imported successfully", e.app.MainWindow)
		e.app.secretsUI.Refresh() // Tell secrets UI to fetch new data
	}, e.app.MainWindow)
}
