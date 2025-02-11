package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"goDriverSigner/internal/config"
	"goDriverSigner/internal/logger"
	"goDriverSigner/internal/signer"
	"goDriverSigner/internal/utils"
)

// Options содержит параметры запуска приложения
type Options struct {
	FilePath     string
	Verify       bool
	Force        bool
	PfxPath      string
	PfxPassword  string
	Org          string
	Country      string
	Offline      bool
	TestMode     bool
	ExportFormat string
	CI           bool
}

// App представляет основное приложение
type App struct {
	config *config.Config
	log    *logger.Logger
	signer *signer.Signer
}

// NewApp создает новый экземпляр приложения
func NewApp(cfg *config.Config, log *logger.Logger) *App {
	return &App{
		config: cfg,
		log:    log,
		signer: signer.NewSigner(cfg, log),
	}
}

// Run запускает приложение с заданными параметрами
func (a *App) Run(opts *Options) error {
	// Проверяем тестовый режим Windows
	if opts.TestMode {
		if err := a.enableTestMode(); err != nil {
			return fmt.Errorf("ошибка включения тестового режима: %v", err)
		}
	}

	// Если указан PFX файл, импортируем его
	if opts.PfxPath != "" {
		if err := a.signer.ImportPFX(opts.PfxPath, opts.PfxPassword); err != nil {
			return fmt.Errorf("ошибка импорта PFX: %v", err)
		}
	}

	// Если нужно экспортировать сертификат
	if opts.ExportFormat != "" {
		return a.exportCertificate(opts.ExportFormat)
	}

	// Проверяем подпись
	if opts.Verify {
		return a.verifySignature(opts.FilePath)
	}

	// Подписываем файл(ы)
	return a.signFiles(opts)
}

// RunInteractive запускает интерактивный режим
func (a *App) RunInteractive() error {
	// TODO: Реализовать интерактивное меню
	return fmt.Errorf("интерактивный режим пока не реализован")
}

// Включает тестовый режим Windows
func (a *App) enableTestMode() error {
	a.log.Info("Включение тестового режима Windows...")
	cmd := exec.Command("bcdedit", "/set", "testsigning", "on")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка: %v, output: %s", err, output)
	}
	a.log.Success("Тестовый режим Windows включен")
	return nil
}

// Экспортирует сертификат в указанном формате
func (a *App) exportCertificate(format string) error {
	switch strings.ToLower(format) {
	case "pem":
		return a.signer.ExportCertificate("pem")
	case "der":
		return a.signer.ExportCertificate("der")
	case "pfx":
		return a.signer.ExportCertificate("pfx")
	default:
		return fmt.Errorf("неподдерживаемый формат экспорта: %s", format)
	}
}

// Проверяет подпись файла
func (a *App) verifySignature(path string) error {
	a.log.Info("Проверка подписи файла %s...", path)
	if err := a.signer.VerifySignature(path); err != nil {
		return fmt.Errorf("ошибка проверки подписи: %v", err)
	}
	a.log.Success("Подпись файла верна")
	return nil
}

// Подписывает файл(ы)
func (a *App) signFiles(opts *Options) error {
	// Проверяем, является ли путь шаблоном
	if strings.ContainsAny(opts.FilePath, "*?") {
		return a.signMultipleFiles(opts)
	}
	return a.signSingleFile(opts)
}

// Подписывает один файл
func (a *App) signSingleFile(opts *Options) error {
	a.log.Info("Подпись файла %s...", opts.FilePath)
	
	// Проверяем расширение
	ext := strings.ToLower(filepath.Ext(opts.FilePath))
	if ext != ".sys" && ext != ".inf" && ext != ".cat" {
		return fmt.Errorf("неподдерживаемый тип файла: %s", ext)
	}

	// Подписываем файл
	if err := a.signer.SignFile(opts.FilePath, opts.Force); err != nil {
		return fmt.Errorf("ошибка подписи файла: %v", err)
	}

	a.log.Success("Файл успешно подписан")
	return nil
}

// Подписывает несколько файлов по шаблону
func (a *App) signMultipleFiles(opts *Options) error {
	files, err := filepath.Glob(opts.FilePath)
	if err != nil {
		return fmt.Errorf("ошибка поиска файлов: %v", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("файлы не найдены: %s", opts.FilePath)
	}

	a.log.Info("Найдено файлов: %d", len(files))

	for i, file := range files {
		a.log.Progress(i+1, len(files), fmt.Sprintf("Подпись файла %s", filepath.Base(file)))
		
		opts.FilePath = file
		if err := a.signSingleFile(opts); err != nil {
			if !opts.CI { // В режиме CI останавливаемся при первой ошибке
				a.log.Error("Ошибка подписи %s: %v", file, err)
				continue
			}
			return err
		}
	}

	return nil
} 