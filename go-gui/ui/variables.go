package ui

import (
	"context"
	"errors"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/secretserver-clients/go/secretserver"
	"time"
)

func (a *App) variablesPanel() fyne.CanvasObject {
	name, kind, id, field := widget.NewEntry(), widget.NewEntry(), widget.NewEntry(), widget.NewEntry()
	name.SetPlaceHolder("LOG_SERVER_TX1_S")
	kind.SetText("password")
	field.SetText("value")
	assign := widget.NewButton("Save assignment", func() {
		if a.Client == nil {
			dialog.ShowError(errors.New("configure an API account first"), a.MainWindow)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, err := a.Client.AssignVariable(ctx, name.Text, secretserver.VariableAssignment{SecretType: kind.Text, SecretID: id.Text, Field: field.Text})
		if err != nil {
			dialog.ShowError(errors.New("assignment failed; check credential and permissions"), a.MainWindow)
			return
		}
		dialog.ShowInformation("Variable saved", "Consumers can now resolve %%"+name.Text+"%%", a.MainWindow)
	})
	template := widget.NewMultiLineEntry()
	template.SetPlaceHolder("%%LOG_SERVER_TX1_S%%")
	result := widget.NewPasswordEntry()
	render := widget.NewButton("Resolve template", func() {
		result.SetText("")
		if a.Client == nil {
			dialog.ShowError(errors.New("configure an API account first"), a.MainWindow)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		value, err := a.Client.Render(ctx, template.Text)
		if err != nil {
			dialog.ShowError(errors.New("resolution failed; check assignments and permissions"), a.MainWindow)
			return
		}
		result.SetText(value)
	})
	return container.NewVBox(widget.NewLabel("Variable assignments contain references to credential fields."), widget.NewForm(widget.NewFormItem("Name", name), widget.NewFormItem("Credential type", kind), widget.NewFormItem("Credential UUID", id), widget.NewFormItem("Field", field)), assign, widget.NewLabel("Resolved results contain secrets and remain in memory until cleared."), template, render, result, widget.NewButton("Clear result", func() { result.SetText("") }))
}
