package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"goDriverSigner/internal/app"
	"goDriverSigner/internal/config"
	"goDriverSigner/internal/logger"
	"goDriverSigner/internal/utils"
)

var (
	// Флаги командной строки
	filePath    = flag.String("file", "", "Путь к драйверу для подписи (.sys, .inf или .cat файл)")
	verify      = flag.Bool("verify", false, "Проверить подпись драйвера")
	force       = flag.Bool("force", false, "Принудительно пересоздать сертификат")
	verbose     = flag.Bool("verbose", false, "Подробный режим логирования")
	interactive = flag.Bool("interactive", false, "Интерактивный режим")
	pfxPath     = flag.String("pfx", "", "Путь к PFX файлу для импорта")
	pfxPassword = flag.String("pfx-password", "", "Пароль для PFX файла")
	org         = flag.String("org", "", "Название организации для сертификата")
	country     = flag.String("country", "", "Код страны для сертификата (например, RU)")
	offline     = flag.Bool("offline", false, "Режим офлайн установки")
	testMode    = flag.Bool("test-mode", false, "Включить тестовый режим Windows")
	exportCert  = flag.String("export", "", "Экспортировать сертификат (формат: pem, der, pfx)")
	ci          = flag.Bool("ci", false, "Режим CI/CD (без интерактивных запросов)")
)

func main() {
	flag.Parse()

	// Инициализация логгера
	log := logger.NewLogger(*verbose)

	// Проверка прав администратора
	if !utils.IsAdmin() {
		log.Fatal("Эта программа требует прав администратора")
	}

	// Загрузка конфигурации
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	// Создание экземпляра приложения
	application := app.NewApp(cfg, log)

	// Если выбран интерактивный режим
	if *interactive {
		if err := application.RunInteractive(); err != nil {
			log.Fatalf("Ошибка в интерактивном режиме: %v", err)
		}
		return
	}

	// Проверка обязательных параметров
	if *filePath == "" && !*interactive && *exportCert == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Настройка приложения
	opts := &app.Options{
		FilePath:    *filePath,
		Verify:      *verify,
		Force:       *force,
		PfxPath:     *pfxPath,
		PfxPassword: *pfxPassword,
		Org:         *org,
		Country:     *country,
		Offline:     *offline,
		TestMode:    *testMode,
		ExportFormat: *exportCert,
		CI:          *ci,
	}

	// Запуск приложения
	if err := application.Run(opts); err != nil {
		log.Fatalf("Ошибка: %v", err)
	}
} 