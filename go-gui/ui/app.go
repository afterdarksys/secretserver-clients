package ui

import (
	"context"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"github.com/afterdarksys/secretserver-clients/go/secretserver"
)

// App holds the application state
type App struct {
	FyneApp    fyne.App
	MainWindow fyne.Window
	Client     *secretserver.Client
	Tabs       *container.AppTabs
	// clientErr explains why Client is nil (keychain or URL problem).
	clientErr error
	// account describes the active credential (never a token).
	account string

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

// initClient builds the client from the stored credential choice: the
// keychain API key or the `ss login` session. On failure Client is nil and
// clientErr says why; plaintext is never used.
func (a *App) initClient() {
	a.Client, a.account, a.clientErr = buildClient(context.Background(), a.FyneApp.Preferences())
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
		container.NewTabItem("Documents", a.documentsPanel()),
		container.NewTabItem("Extractor", a.extractorUI.Content),
		container.NewTabItem("Settings", a.settingsUI.Content),
	)

	a.Tabs.SetTabLocation(container.TabLocationTop)

	return a.Tabs
}
