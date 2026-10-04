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

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	showStatus := func() {
		switch {
		case app.Client != nil:
			status.SetText("Signed in: " + app.account)
		case app.clientErr != nil:
			status.SetText("Not connected: " + app.clientErr.Error())
		default:
			status.SetText("Not configured")
		}
	}
	showStatus()

	const (
		optAPIKey   = "API key (OS keychain)"
		optCLILogin = "Sign in with ss login"
	)
	mode := widget.NewRadioGroup([]string{optAPIKey, optCLILogin}, func(choice string) {
		if choice == optCLILogin {
			apiKey.Disable()
			apiURL.SetPlaceHolder("Empty: use the URL from ss login")
		} else {
			apiKey.Enable()
		}
	})
	mode.Required = true
	if authMode(app.FyneApp.Preferences()) == authModeCLILogin {
		apiURL.SetText(app.FyneApp.Preferences().String(prefAPIURL))
		mode.SetSelected(optCLILogin)
	} else {
		mode.SetSelected(optAPIKey)
	}

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "Sign in", Widget: mode, HintText: "ss login reuses the CLI's SSO session; no token is stored here"},
			{Text: "API URL", Widget: apiURL, HintText: "https:// (http only for localhost)"},
			{Text: "API Key", Widget: apiKey, HintText: "Your Secret Server API key (leave empty to keep the stored key)"},
		},
		OnSubmit: func() {
			prefs := app.FyneApp.Preferences()
			if mode.Selected == optCLILogin {
				// Persist only the choice and the (optional) URL; the token
				// stays with the CLI.
				prefs.SetString(prefAuthMode, authModeCLILogin)
				if apiURL.Text == "" {
					prefs.RemoveValue(prefAPIURL)
				} else {
					prefs.SetString(prefAPIURL, apiURL.Text)
				}
				err := app.ReloadClient()
				showStatus()
				if err != nil {
					dialog.ShowError(err, app.MainWindow)
					return
				}
				dialog.ShowInformation("Signed in", "Using "+app.account+".", app.MainWindow)
				return
			}
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
			prefs.SetString(prefAuthMode, authModeAPIKey)
			err := app.ReloadClient()
			showStatus()
			if err != nil {
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
		status,
	)

	s.Content = container.NewPadded(content)
	return s
}
