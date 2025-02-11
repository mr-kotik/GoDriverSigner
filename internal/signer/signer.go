package signer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"goDriverSigner/internal/config"
	"goDriverSigner/internal/logger"
	"software.sslmate.com/src/go-pkcs12"
)

// Signer представляет модуль для работы с подписью
type Signer struct {
	config *config.Config
	log    *logger.Logger
}

// NewSigner создает новый экземпляр модуля подписи
func NewSigner(cfg *config.Config, log *logger.Logger) *Signer {
	return &Signer{
		config: cfg,
		log:    log,
	}
}

// SignFile подписывает файл
func (s *Signer) SignFile(path string, force bool) error {
	// Получаем сертификат и ключ
	cert, key, err := s.getCertificate(force)
	if err != nil {
		return err
	}

	// Создаем временный PFX файл
	pfxPath, err := s.createTempPFX(cert, key)
	if err != nil {
		return err
	}
	defer os.Remove(pfxPath)

	// Подписываем файл с помощью signtool
	return s.signWithSigntool(path, pfxPath)
}

// VerifySignature проверяет подпись файла
func (s *Signer) VerifySignature(path string) error {
	cmd := exec.Command("signtool", "verify", "/pa", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка проверки подписи: %v\nOutput: %s", err, output)
	}
	return nil
}

// ImportPFX импортирует сертификат из PFX файла
func (s *Signer) ImportPFX(path, password string) error {
	// Читаем PFX файл
	pfxData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Расшифровываем PFX
	key, cert, err := pkcs12.Decode(pfxData, password)
	if err != nil {
		return err
	}

	// Сохраняем сертификат и ключ
	return s.saveCertAndKey(cert, key.(*rsa.PrivateKey))
}

// ExportCertificate экспортирует сертификат в указанном формате
func (s *Signer) ExportCertificate(format string) error {
	cert, key, err := s.loadCertAndKey()
	if err != nil {
		return err
	}

	outFile := fmt.Sprintf("certificate.%s", format)
	switch format {
	case "pem":
		return s.exportPEM(outFile, cert, key)
	case "der":
		return s.exportDER(outFile, cert)
	case "pfx":
		return s.exportPFX(outFile, cert, key)
	default:
		return fmt.Errorf("неподдерживаемый формат: %s", format)
	}
}

// Внутренние методы

func (s *Signer) getCertificate(force bool) (*x509.Certificate, *rsa.PrivateKey, error) {
	if !force {
		// Пытаемся загрузить существующий сертификат
		cert, key, err := s.loadCertAndKey()
		if err == nil {
			return cert, key, nil
		}
		s.log.Warning("Не удалось загрузить существующий сертификат: %v", err)
	}

	// Создаем новый сертификат
	return s.createNewCertificate()
}

func (s *Signer) createNewCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	s.log.Info("Создание нового сертификата...")

	// Генерируем ключ
	key, err := rsa.GenerateKey(rand.Reader, s.config.KeySize)
	if err != nil {
		return nil, nil, err
	}

	// Создаем шаблон сертификата
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   "GoDriverSigner",
			Organization: []string{"GoDriverSigner"},
			Country:      []string{"RU"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(s.config.CertValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Создаем сертификат
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	// Сохраняем сертификат и ключ
	if err := s.saveCertAndKey(cert, key); err != nil {
		return nil, nil, err
	}

	s.log.Success("Новый сертификат создан")
	return cert, key, nil
}

func (s *Signer) loadCertAndKey() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Читаем сертификат
	certPEM, err := os.ReadFile(s.config.CertPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("не удалось декодировать PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Читаем ключ
	keyPEM, err := os.ReadFile(s.config.KeyPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("не удалось декодировать PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func (s *Signer) saveCertAndKey(cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Сохраняем сертификат
	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	if err := os.WriteFile(s.config.CertPath, certOut.Bytes(), 0644); err != nil {
		return err
	}

	// Сохраняем ключ
	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	if err := os.WriteFile(s.config.KeyPath, keyOut.Bytes(), 0600); err != nil {
		return err
	}

	return nil
}

func (s *Signer) createTempPFX(cert *x509.Certificate, key *rsa.PrivateKey) (string, error) {
	// Создаем PFX
	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, "")
	if err != nil {
		return "", err
	}

	// Сохраняем во временный файл
	tempFile, err := os.CreateTemp("", "cert*.pfx")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	if _, err := tempFile.Write(pfxData); err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

func (s *Signer) signWithSigntool(path, pfxPath string) error {
	args := []string{
		"sign",
		"/f", pfxPath,
		"/fd", "sha256",
	}

	// Добавляем timestamp сервер
	if len(s.config.TimeServers) > 0 {
		args = append(args, "/t", s.config.TimeServers[0])
	}

	args = append(args, path)

	cmd := exec.Command("signtool", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка подписи: %v\nOutput: %s", err, output)
	}

	return nil
}

func (s *Signer) exportPEM(outFile string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	// Экспортируем сертификат
	certOut := new(bytes.Buffer)
	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Экспортируем ключ
	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Объединяем в один файл
	out := append(certOut.Bytes(), keyOut.Bytes()...)
	return os.WriteFile(outFile, out, 0600)
}

func (s *Signer) exportDER(outFile string, cert *x509.Certificate) error {
	return os.WriteFile(outFile, cert.Raw, 0644)
}

func (s *Signer) exportPFX(outFile string, cert *x509.Certificate, key *rsa.PrivateKey) error {
	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, "")
	if err != nil {
		return err
	}
	return os.WriteFile(outFile, pfxData, 0600)
} 