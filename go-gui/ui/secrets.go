package ui

import (
	"context"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/afterdarksys/secretserver-go/secretserver"
)

// SecretsUI manages the secrets view
type SecretsUI struct {
	app     *App
	Content fyne.CanvasObject
	list    *widget.List
	secrets []*secretserver.Secret
	details *fyne.Container
}

// NewSecretsUI creates the secrets UI
func NewSecretsUI(app *App) *SecretsUI {
	s := &SecretsUI{
		app:     app,
		secrets: []*secretserver.Secret{},
	}

	s.list = widget.NewList(
		func() int { return len(s.secrets) },
		func() fyne.CanvasObject {
			return widget.NewLabel("Template Label - Placeholder Text For Loading")
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(s.secrets[i].Name)
		},
	)

	s.list.OnSelected = func(id widget.ListItemID) {
		s.showDetails(s.secrets[id])
	}

	s.details = container.NewVBox(widget.NewLabel("Select a secret to view details"))

	refreshBtn := widget.NewButton("Refresh", func() {
		s.Refresh()
	})

	createBtn := widget.NewButton("New Secret", func() {
		s.showCreateForm()
	})

	toolbar := container.NewHBox(refreshBtn, createBtn, layout.NewSpacer())

	left := container.NewBorder(toolbar, nil, nil, nil, s.list)
	split := container.NewHSplit(left, container.NewScroll(s.details))
	split.Offset = 0.3

	s.Content = container.NewPadded(split)

	return s
}

// Refresh loads secrets from the server
func (s *SecretsUI) Refresh() {
	if s.app.Client == nil {
		s.secrets = nil
		s.list.Refresh()
		s.details.Objects = []fyne.CanvasObject{widget.NewLabel("Client not configured. Please set API credentials in Settings.")}
		s.details.Refresh()
		return
	}

	secrets, err := s.app.Client.Secrets.List(context.Background(), nil)
	if err != nil {
		dialog.ShowError(err, s.app.MainWindow)
		return
	}

	s.secrets = secrets
	s.list.Refresh()
	if len(s.secrets) == 0 {
		s.details.Objects = []fyne.CanvasObject{widget.NewLabel("No secrets found.")}
	} else {
		s.details.Objects = []fyne.CanvasObject{widget.NewLabel("Select a secret from the list.")}
	}
	s.details.Refresh()
}

func (s *SecretsUI) showDetails(sec *secretserver.Secret) {
	title := widget.NewLabelWithStyle(sec.Name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	desc := widget.NewLabel(sec.Description)

	dataStr := ""
	for k, v := range sec.Data {
		dataStr += fmt.Sprintf("%s: %s\n", k, v)
	}

	dataLabel := widget.NewLabel(dataStr)
	
	editBtn := widget.NewButton("Edit", func() {
		s.showEditForm(sec)
	})

	delBtn := widget.NewButton("Delete", func() {
		s.deleteSecret(sec)
	})

	actions := container.NewHBox(editBtn, delBtn)

	s.details.Objects = []fyne.CanvasObject{
		title,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Description:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		desc,
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Data:", fyne.TextAlignLeading, fyne.TextStyle{Italic: true}),
		dataLabel,
		widget.NewSeparator(),
		actions,
	}
	s.details.Refresh()
}

func (s *SecretsUI) deleteSecret(sec *secretserver.Secret) {
	dialog.ShowConfirm("Delete", fmt.Sprintf("Are you sure you want to delete '%s'?", sec.Name), func(b bool) {
		if !b {
			return
		}
		err := s.app.Client.Secrets.Delete(context.Background(), sec.Name)
		if err != nil {
			dialog.ShowError(err, s.app.MainWindow)
			return
		}
		s.Refresh()
	}, s.app.MainWindow)
}

func (s *SecretsUI) showCreateForm() {
	nameEntry := widget.NewEntry()
	descEntry := widget.NewEntry()
	dataEntry := widget.NewMultiLineEntry()
	dataEntry.PlaceHolder = "key=value\nkey2=value2"

	items := []*widget.FormItem{
		{Text: "Name", Widget: nameEntry},
		{Text: "Description", Widget: descEntry},
		{Text: "Data (K=V pairs)", Widget: dataEntry},
	}

	dialog.ShowForm("New Secret", "Create", "Cancel", items, func(b bool) {
		if !b {
			return
		}
		dataMap := make(map[string]string)
		for _, line := range strings.Split(dataEntry.Text, "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				dataMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		req := &secretserver.SecretCreateRequest{
			Name:        nameEntry.Text,
			Description: descEntry.Text,
			Data:        dataMap,
		}

		_, err := s.app.Client.Secrets.Create(context.Background(), req)
		if err != nil {
			dialog.ShowError(err, s.app.MainWindow)
			return
		}
		s.Refresh()
	}, s.app.MainWindow)
}

func (s *SecretsUI) showEditForm(sec *secretserver.Secret) {
	nameEntry := widget.NewEntry()
	nameEntry.SetText(sec.Name)
	nameEntry.Disable() // Assuming name cannot be changed easily without rename API

	descEntry := widget.NewEntry()
	descEntry.SetText(sec.Description)

	dataStr := ""
	for k, v := range sec.Data {
		dataStr += fmt.Sprintf("%s=%s\n", k, v)
	}
	dataEntry := widget.NewMultiLineEntry()
	dataEntry.SetText(dataStr)

	items := []*widget.FormItem{
		{Text: "Name", Widget: nameEntry},
		{Text: "Description", Widget: descEntry},
		{Text: "Data (K=V pairs)", Widget: dataEntry},
	}

	dialog.ShowForm("Edit Secret", "Save", "Cancel", items, func(b bool) {
		if !b {
			return
		}
		dataMap := make(map[string]string)
		for _, line := range strings.Split(dataEntry.Text, "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				dataMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}

		req := &secretserver.SecretUpdateRequest{
			Description: descEntry.Text,
			Data:        dataMap,
		}

		_, err := s.app.Client.Secrets.Update(context.Background(), sec.Name, req)
		if err != nil {
			dialog.ShowError(err, s.app.MainWindow)
			return
		}
		s.Refresh()
	}, s.app.MainWindow)
}
