package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"net/url"
)

func (a *App) documentsPanel() fyne.CanvasObject {
	address := widget.NewEntry()
	address.SetText("https://secretserver.io/documents")
	text := widget.NewLabel("Manage protected PDFs in the web console: upload, preview, expiring shares, revoke, download and print permissions. Sign in separately in your browser. For self-hosting, enter your trusted web console URL. Visible content can still be captured.")
	text.Wrapping = fyne.TextWrapWord
	return container.NewVBox(text, address, widget.NewButton("Open document manager", func() {
		u, err := url.Parse(address.Text)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			dialog.ShowInformation("Invalid address", "Enter an HTTPS web console URL without credentials or query parameters.", a.MainWindow)
			return
		}
		if err = a.FyneApp.OpenURL(u); err != nil {
			dialog.ShowError(err, a.MainWindow)
		}
	}))
}
