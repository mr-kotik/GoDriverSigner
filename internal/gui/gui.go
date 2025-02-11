package gui

import (
	"fmt"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"path/filepath"
)

type MainWindow struct {
	*walk.MainWindow
	dropFiles *walk.TextEdit
	progress  *walk.ProgressBar
}

func RunGUI(app *App) error {
	mw := &MainWindow{}

	icon, _ := walk.NewIconFromFile("icon.ico")

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "GoDriverSigner",
		MinSize:  Size{600, 400},
		Layout:   VBox{},
		Icon:     icon,
		MenuItems: []MenuItem{
			Menu{
				Text: "&Файл",
				Items: []MenuItem{
					Action{
						Text: "Подписать драйвер...",
						OnTriggered: func() {
							if file := openFileDialog(mw); file != "" {
								go app.SignFile(file)
							}
						},
					},
					Action{
						Text: "Проверить подпись...",
						OnTriggered: func() {
							if file := openFileDialog(mw); file != "" {
								go app.VerifySignature(file)
							}
						},
					},
					Separator{},
					Action{
						Text: "Выход",
						OnTriggered: func() {
							mw.Close()
						},
					},
				},
			},
			Menu{
				Text: "&Сертификат",
				Items: []MenuItem{
					Action{
						Text: "Создать новый...",
						OnTriggered: func() {
							go app.CreateNewCertificate()
						},
					},
					Action{
						Text: "Импорт...",
						OnTriggered: func() {
							if file := openFileDialog(mw); file != "" {
								go app.ImportCertificate(file)
							}
						},
					},
					Action{
						Text: "Экспорт...",
						OnTriggered: func() {
							go app.ExportCertificate()
						},
					},
				},
			},
			Menu{
				Text: "&Инструменты",
				Items: []MenuItem{
					Action{
						Text: "Настройки...",
						OnTriggered: func() {
							showSettings(mw)
						},
					},
					Action{
						Text: "Тестовый режим Windows",
						OnTriggered: func() {
							go app.EnableTestMode()
						},
					},
				},
			},
		},
		Children: []Widget{
			GroupBox{
				Title:  "Перетащите файлы сюда",
				Layout: HBox{},
				Children: []Widget{
					TextEdit{
						AssignTo:    &mw.dropFiles,
						ReadOnly:    true,
						AcceptFiles: true,
						OnDropFiles: func(files []string) {
							for _, file := range files {
								if ext := filepath.Ext(file); ext == ".sys" || ext == ".inf" || ext == ".cat" {
									go app.SignFile(file)
								}
							}
						},
					},
				},
			},
			ProgressBar{
				AssignTo: &mw.progress,
				MinValue: 0,
				MaxValue: 100,
			},
		},
	}.Create()); err != nil {
		return err
	}

	// Добавляем иконку в трей
	ni, err := walk.NewNotifyIcon(mw)
	if err != nil {
		return err
	}
	defer ni.Dispose()

	if err := ni.SetIcon(icon); err != nil {
		return err
	}
	if err := ni.SetToolTip("GoDriverSigner"); err != nil {
		return err
	}

	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			mw.Show()
		}
	})

	mw.Run()
	return nil
}

func openFileDialog(owner walk.Form) string {
	dlg := new(walk.FileDialog)
	dlg.Title = "Выберите файл"
	dlg.Filter = "Драйверы (*.sys;*.inf;*.cat)|*.sys;*.inf;*.cat|Все файлы (*.*)|*.*"

	if ok, _ := dlg.ShowOpen(owner); !ok {
		return ""
	}
	return dlg.FilePath
}

func showSettings(owner walk.Form) {
	var dlg *walk.Dialog
	var db *walk.DataBinder

	Dialog{
		AssignTo:      &dlg,
		Title:         "Настройки",
		DefaultButton: &PushButton{Text: "OK"},
		CancelButton:  &PushButton{Text: "Отмена"},
		DataBinder: DataBinder{
			AssignTo:   &db,
			DataSource: settings,
		},
		MinSize: Size{300, 300},
		Layout:  VBox{},
		Children: []Widget{
			GroupBox{
				Title:  "Основные",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Организация:"},
					LineEdit{Text: Bind("Organization")},
					Label{Text: "Страна:"},
					LineEdit{Text: Bind("Country")},
				},
			},
			GroupBox{
				Title:  "Сертификат",
				Layout: Grid{Columns: 2},
				Children: []Widget{
					Label{Text: "Срок действия (лет):"},
					NumberEdit{Value: Bind("ValidityYears")},
					Label{Text: "Размер ключа:"},
					NumberEdit{Value: Bind("KeySize")},
				},
			},
		},
	}.Run(owner)
} 