package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	// Пути к файлам
	CertPath    string `json:"cert_path"`
	KeyPath     string `json:"key_path"`
	BackupDir   string `json:"backup_dir"`
	LogDir      string `json:"log_dir"`

	// Настройки сертификата
	CertValidityYears int      `json:"cert_validity_years"`
	TimeServers       []string `json:"time_servers"`
	KeySize           int      `json:"key_size"`

	// Настройки SDK
	SDKOfflinePath string   `json:"sdk_offline_path"`
	SDKUrls        []string `json:"sdk_urls"`

	// Настройки безопасности
	KeyEncryption bool `json:"key_encryption"`
	
	// Настройки CI/CD
	CIMode bool `json:"ci_mode"`
}

// Значения по умолчанию
var defaultConfig = Config{
	CertValidityYears: 10,
	KeySize:           4096,
	TimeServers: []string{
		"http://timestamp.digicert.com",
		"http://timestamp.globalsign.com/scripts/timstamp.dll",
		"http://timestamp.comodoca.com/authenticode",
	},
	KeyEncryption: true,
}

// Load загружает конфигурацию из файла или создает новую
func Load() (*Config, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(configDir, "config.json")
	
	// Если файл не существует, создаем его
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return createDefaultConfig(configPath)
	}

	// Читаем существующий файл
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// Создает директорию конфигурации
func getConfigDir() (string, error) {
	userHome, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	configDir := filepath.Join(userHome, ".goDriverSigner")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", err
	}

	return configDir, nil
}

// Создает файл конфигурации по умолчанию
func createDefaultConfig(path string) (*Config, error) {
	config := defaultConfig

	// Устанавливаем пути по умолчанию
	configDir := filepath.Dir(path)
	config.CertPath = filepath.Join(configDir, "cert.pem")
	config.KeyPath = filepath.Join(configDir, "key.pem")
	config.BackupDir = filepath.Join(configDir, "backup")
	config.LogDir = filepath.Join(configDir, "logs")

	// Создаем необходимые директории
	dirs := []string{
		config.BackupDir,
		config.LogDir,
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	// Сохраняем конфигурацию
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return nil, err
	}

	return &config, nil
} 