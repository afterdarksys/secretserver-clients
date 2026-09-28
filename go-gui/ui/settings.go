package ui

import (
	"errors"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/secretserver-clients/go/secretserver"
)

// SettingsUI manages the configuration view
type SettingsUI struct {
	app     *App
	Content fyne.CanvasObject
}

// NewSettingsUI creates the settings UI. The API key is kept in the OS
// keychain, never in preferences; the field starts empty and leaving it empty
// keeps the stored key.
func NewSettingsUI(app *App) *SettingsUI {
	s := &SettingsUI{
		app: app,
	}

	apiURL := widget.NewEntry()
	apiURL.SetText(app.FyneApp.Preferences().StringWithFallback(prefAPIURL, defaultAPIURL))

	apiKey := widget.NewPasswordEntry()
	apiKey.SetPlaceHolder("Stored in the OS keychain")

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "API URL", Widget: apiURL, HintText: "https:// (http only for localhost)"},
			{Text: "API Key", Widget: apiKey, HintText: "Your Secret Server API key (leave empty to keep the stored key)"},
		},
		OnSubmit: func() {
			prefs := app.FyneApp.Preferences()
			key := apiKey.Text
			if key == "" && apiURL.Text == prefs.StringWithFallback(prefAPIURL, defaultAPIURL) {
				stored, err := loadAPIKey(prefs, apiURL.Text)
				if err != nil {
					dialog.ShowError(err, app.MainWindow)
					return
				}
				key = stored
			}
			if apiURL.Text == "" || key == "" {
				dialog.ShowError(errors.New("please fill in both URL and key"), app.MainWindow)
				return
			}

			// Same validation the SDK applies: https unless loopback, no
			// credentials in the URL.
			if _, err := secretserver.NewClient(&secretserver.Config{APIURL: apiURL.Text, APIKey: key}); err != nil {
				dialog.ShowError(err, app.MainWindow)
				return
			}

			if err := saveAPIKey(prefs, apiURL.Text, key); err != nil {
				dialog.ShowError(err, app.MainWindow)
				return
			}
			apiKey.SetText("")
			if err := app.ReloadClient(); err != nil {
				dialog.ShowError(err, app.MainWindow)
				return
			}

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
