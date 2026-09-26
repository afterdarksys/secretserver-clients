package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"github.com/afterdarksys/secretserver-go/secretserver"
)

// App holds the application state
type App struct {
	FyneApp    fyne.App
	MainWindow fyne.Window
	Client     *secretserver.Client
	Tabs       *container.AppTabs
	// clientErr explains why Client is nil (keychain or URL problem).
	clientErr error

	// UI Components
	settingsUI  *SettingsUI
	secretsUI   *SecretsUI
	extractorUI *ExtractorUI
}

// NewApp creates a new application state
func NewApp(fyneApp fyne.App, window fyne.Window) *App {
	app := &App{
		FyneApp:    fyneApp,
		MainWindow: window,
	}

	app.initClient()

	app.settingsUI = NewSettingsUI(app)
	app.secretsUI = NewSecretsUI(app)
	app.extractorUI = NewExtractorUI(app)

	return app
}

// initClient builds the client from the stored URL and the keychain API key.
// On failure Client is nil and clientErr says why; plaintext is never used.
func (a *App) initClient() {
	a.Client, a.clientErr = nil, nil
	prefs := a.FyneApp.Preferences()
	apiURL := prefs.StringWithFallback(prefAPIURL, defaultAPIURL)
	apiKey, err := loadAPIKey(prefs, apiURL)
	if err != nil {
		a.clientErr = err
		return
	}
	if apiKey == "" {
		return
	}

	client, err := secretserver.NewClient(&secretserver.Config{
		APIURL:    apiURL,
		APIKey:    apiKey,
		UserAgent: "SecretServer-GUI/1.0",
	})
	if err != nil {
		a.clientErr = err
		return
	}
	a.Client = client
}

// ReloadClient is called when settings change
func (a *App) ReloadClient() error {
	a.initClient()
	a.secretsUI.Refresh()
	return a.clientErr
}

// BuildUI constructs the main tabbed interface
func (a *App) BuildUI() fyne.CanvasObject {
	a.Tabs = container.NewAppTabs(
		container.NewTabItem("Secrets", a.secretsUI.Content),
		container.NewTabItem("Variables", a.variablesPanel()),
		container.NewTabItem("Extractor", a.extractorUI.Content),
		container.NewTabItem("Settings", a.settingsUI.Content),
	)

	a.Tabs.SetTabLocation(container.TabLocationTop)

	return a.Tabs
}
