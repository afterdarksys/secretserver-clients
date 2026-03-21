package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	guiui "github.com/afterdarksys/secretserver-gui/ui"
)

func main() {
	a := app.NewWithID("com.afterdarksys.secretserver")
	w := a.NewWindow("Secret Server")

	// Create application state
	guiApp := guiui.NewApp(a, w)

	// Set the main window content
	w.SetContent(guiApp.BuildUI())
	w.Resize(fyne.NewSize(800, 600))
	w.SetMaster()

	w.ShowAndRun()
}
