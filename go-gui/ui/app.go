package ui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"github.com/afterdarksys/secretserver-go/secretserver"
)

// App holds the application state
type App struct {
	FyneApp        fyne.App
	MainWindow     fyne.Window
	Client         *secretserver.Client
	Tabs           *container.AppTabs
	
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

// initClient initializes the secretserver client based on stored preferences
func (a *App) initClient() {
	apiURL := a.FyneApp.Preferences().StringWithFallback("api_url", "https://api.secretserver.io")
	apiKey := a.FyneApp.Preferences().String("api_key")

	if apiKey == "" {
		a.Client = nil
		return
	}

	cfg := &secretserver.Config{
		APIURL:    apiURL,
		APIKey:    apiKey,
		UserAgent: "SecretServer-GUI/1.0",
	}

	client, err := secretserver.NewClient(cfg)
	if err == nil {
		a.Client = client
	}
}

// ReloadClient is called when settings change
func (a *App) ReloadClient() {
	a.initClient()
	a.secretsUI.Refresh()
}

// BuildUI constructs the main tabbed interface
func (a *App) BuildUI() fyne.CanvasObject {
	a.Tabs = container.NewAppTabs(
		container.NewTabItem("Secrets", a.secretsUI.Content),
		container.NewTabItem("Extractor", a.extractorUI.Content),
		container.NewTabItem("Settings", a.settingsUI.Content),
	)

	a.Tabs.SetTabLocation(container.TabLocationTop)

	return a.Tabs
}
