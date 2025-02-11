package gui

import (
	"fmt"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"path/filepath"
	"os"
)

type MainWindow struct {
	*walk.MainWindow
	dropFiles *walk.TextEdit
	progress  *walk.ProgressBar
	logView   *walk.TextEdit
	button    *walk.PushButton
}

func RunGUI(app *App) error {
	mw, err := NewMainWindow()
	if err != nil {
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

func NewMainWindow() (*MainWindow, error) {
	mw := &MainWindow{}

	if err := (walk.MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "GoDriverSigner",
		MinSize:  walk.Size{Width: 800, Height: 600},
		Layout:   walk.VBox{},
		MenuItems: []walk.MenuItem{
			walk.Menu{
				Text: "&Файл",
				Items: []walk.MenuItem{
					walk.Action{
						Text: "Подписать драйвер...",
						OnTriggered: func() {
							mw.selectAndSignFile()
						},
					},
					walk.Action{
						Text: "Проверить подпись...",
						OnTriggered: func() {
							mw.verifySignature()
						},
					},
					walk.Separator{},
					walk.Action{
						Text: "Выход",
						OnTriggered: func() {
							mw.Close()
						},
					},
				},
			},
			walk.Menu{
				Text: "&Сертификат",
				Items: []walk.MenuItem{
					walk.Action{
						Text: "Создать новый сертификат",
						OnTriggered: func() {
							go func() {
								mw.logMessage("Создание нового сертификата...")
								mw.setProgress(20)
								
								cert, _, err := createAndInstallCertificate()
								mw.Synchronize(func() {
									if err != nil {
										mw.showError("Ошибка создания сертификата", err)
										mw.logMessage(fmt.Sprintf("Ошибка: Не удалось создать сертификат: %v", err))
									} else {
										mw.logMessage(fmt.Sprintf("Сертификат успешно создан\nСерийный номер: %s", cert.SerialNumber))
										certInfo := listExistingCertificates()
										mw.logMessage("\nТекущий сертификат:\n" + certInfo)
									}
									mw.setProgress(100)
								})
							}()
						},
					},
					walk.Action{
						Text: "Импорт сертификата...",
						OnTriggered: func() {
							mw.importCertificate()
						},
					},
					walk.Action{
						Text: "Экспорт сертификата...",
						OnTriggered: func() {
							mw.exportCertificate()
						},
					},
				},
			},
			walk.Menu{
				Text: "&Драйвер",
				Items: []walk.MenuItem{
					walk.Action{
						Text: "Установить драйвер...",
						OnTriggered: func() {
							mw.installDriver()
						},
					},
					walk.Action{
						Text: "Удалить драйвер...",
						OnTriggered: func() {
							mw.uninstallDriver()
						},
					},
				},
			},
			walk.Menu{
				Text: "&Помощь",
				Items: []walk.MenuItem{
					walk.Action{
						Text: "О программе",
						OnTriggered: func() {
							walk.MsgBox(mw, "О программе",
								"GoDriverSigner - утилита для подписи драйверов Windows\n"+
									"Версия: "+Version+"\n\n"+
									"Автор: Александр Котик\n"+
									"Лицензия: MIT",
								walk.MsgBoxIconInformation)
						},
					},
				},
			},
		},
		Children: []walk.Widget{
			walk.HSplitter{
				Children: []walk.Widget{
					walk.TextEdit{
						AssignTo: &mw.logView,
						ReadOnly: true,
						MinSize:  walk.Size{Width: 200},
					},
				},
			},
			walk.ProgressBar{
				AssignTo:    &mw.progressBar,
				MarqueeMode: true,
			},
			walk.PushButton{
				AssignTo: &mw.button,
				Text:     "Подписать драйвер",
				OnClicked: func() {
					mw.selectAndSignFile()
				},
			},
		},
	}.Create()); err != nil {
		return nil, err
	}

	// Добавляем обработчик закрытия окна
	mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		*canceled = false
		os.Exit(0)
	})

	// Центрируем окно
	mw.SetSize(walk.Size{Width: 800, Height: 600})
	bounds := mw.Bounds()
	if screen, err := walk.Screens(); err == nil {
		bounds.X = (screen.Bounds().Width - bounds.Width) / 2
		bounds.Y = (screen.Bounds().Height - bounds.Height) / 2
		mw.SetBounds(bounds)
	}

	return mw, nil
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
} 