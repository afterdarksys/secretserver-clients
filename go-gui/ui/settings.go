package ui

import (
	"errors"
	"log"
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// SettingsUI manages the configuration view
type SettingsUI struct {
	app     *App
	Content fyne.CanvasObject
}

// NewSettingsUI creates the settings UI
func NewSettingsUI(app *App) *SettingsUI {
	s := &SettingsUI{
		app: app,
	}

	apiURL := widget.NewEntry()
	apiURL.SetText(app.FyneApp.Preferences().StringWithFallback("api_url", "https://api.secretserver.io"))
	
	apiKey := widget.NewPasswordEntry()
	apiKey.SetText(app.FyneApp.Preferences().String("api_key"))

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "API URL", Widget: apiURL, HintText: "The Secret Server HTTP API Endpoint"},
			{Text: "API Key", Widget: apiKey, HintText: "Your Secret Server JWT or API token"},
		},
		OnSubmit: func() {
			if apiURL.Text == "" || apiKey.Text == "" {
				dialog.ShowError(errors.New("Please fill in both URL and Key"), app.MainWindow)
				return
			}

			if _, err := url.Parse(apiURL.Text); err != nil {
				dialog.ShowError(errors.New("Invalid API URL format"), app.MainWindow)
				return
			}

			app.FyneApp.Preferences().SetString("api_url", apiURL.Text)
			app.FyneApp.Preferences().SetString("api_key", apiKey.Text)
			app.ReloadClient()

			log.Println("Settings saved successfully")
			dialog.ShowInformation("Success", "Settings have been saved and client initialized.", app.MainWindow)
		},
	}

	content := container.NewVBox(
		widget.NewLabelWithStyle("Configuration", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		form,
	)

	s.Content = container.NewPadded(content)
	return s
}
