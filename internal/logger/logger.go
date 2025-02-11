package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Цвета для консоли
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

type Logger struct {
	verbose bool
	file    io.WriteCloser
}

// NewLogger создает новый логгер
func NewLogger(verbose bool) *Logger {
	// Создаем файл лога
	logFile, err := createLogFile()
	if err != nil {
		fmt.Printf("Ошибка создания файла лога: %v\n", err)
		return &Logger{verbose: verbose}
	}

	return &Logger{
		verbose: verbose,
		file:    logFile,
	}
}

// Info выводит информационное сообщение
func (l *Logger) Info(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.log(colorBlue+"[INFO]"+colorReset+" %s", msg)
}

// Success выводит сообщение об успехе
func (l *Logger) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.log(colorGreen+"[SUCCESS]"+colorReset+" %s", msg)
}

// Warning выводит предупреждение
func (l *Logger) Warning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.log(colorYellow+"[WARNING]"+colorReset+" %s", msg)
}

// Error выводит сообщение об ошибке
func (l *Logger) Error(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.log(colorRed+"[ERROR]"+colorReset+" %s", msg)
}

// Fatal выводит сообщение об ошибке и завершает программу
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.Error(format, args...)
	os.Exit(1)
}

// Verbose выводит подробное сообщение только в verbose режиме
func (l *Logger) Verbose(format string, args ...interface{}) {
	if l.verbose {
		msg := fmt.Sprintf(format, args...)
		l.log("[VERBOSE] %s", msg)
	}
}

// Progress выводит прогресс операции
func (l *Logger) Progress(current, total int, message string) {
	if total <= 0 {
		return
	}
	
	percentage := float64(current) / float64(total) * 100
	width := 40
	completed := int(float64(width) * float64(current) / float64(total))

	bar := "["
	for i := 0; i < width; i++ {
		if i < completed {
			bar += "="
		} else if i == completed {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	fmt.Printf("\r%s %s %.1f%% (%d/%d)", message, bar, percentage, current, total)
	if current == total {
		fmt.Println()
	}
}

// внутренний метод для логирования
func (l *Logger) log(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)
	logMsg := fmt.Sprintf("%s %s\n", timestamp, msg)

	// Вывод в консоль
	fmt.Print(logMsg)

	// Запись в файл без цветовых кодов
	if l.file != nil {
		cleanMsg := stripColors(logMsg)
		l.file.Write([]byte(cleanMsg))
	}
}

// Создает файл для логирования
func createLogFile() (io.WriteCloser, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	logDir := filepath.Join(homeDir, ".goDriverSigner", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return nil, err
	}

	logPath := filepath.Join(logDir, time.Now().Format("2006-01-02_15-04-05")+".log")
	return os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}

// Удаляет цветовые коды ANSI из строки
func stripColors(s string) string {
	colors := []string{
		colorReset,
		colorRed,
		colorGreen,
		colorYellow,
		colorBlue,
	}

	result := s
	for _, color := range colors {
		result = string([]rune(result))
	}
	return result
} 