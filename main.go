package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"golang.org/x/sys/windows"
	"software.sslmate.com/src/go-pkcs12"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"unsafe"
	"crypto/sha1"
)

const (
	certStoreName = "GoDriverSigner"
	certStoreType = "ROOT"
	certFileName  = "goDriverSigner.cer"
	keyFileName   = "goDriverSigner.key"
	
	// URL for downloading Windows SDK
	windowsSDKUrl = "https://go.microsoft.com/fwlink/?linkid=2164145" // Windows SDK for Windows 10
)

func main() {
	// Check administrator rights
	isAdmin, err := checkAdminRights()
	if err != nil {
		walk.MsgBox(nil, "Error",
			fmt.Sprintf("Error checking administrator rights: %v", err),
			walk.MsgBoxIconError)
		return
	}
	if !isAdmin {
		walk.MsgBox(nil, "Error",
			"This program requires administrator rights. Please run it as administrator.",
			walk.MsgBoxIconError)
		return
	}

	// Check and install required components
	if err := checkAndInstallRequirements(); err != nil {
		walk.MsgBox(nil, "Error",
			fmt.Sprintf("Error checking/installing components: %v", err),
			walk.MsgBoxIconError)
		return
	}

	var filePath string
	var guiMode bool
	flag.StringVar(&filePath, "file", "", "Path to driver for signing (.sys or .inf file)")
	flag.BoolVar(&guiMode, "gui", false, "Run in graphical mode")
	flag.Parse()

	// If no flags specified or GUI mode explicitly requested, start graphical interface
	if flag.NFlag() == 0 || guiMode {
		if err := runGUI(); err != nil {
			walk.MsgBox(nil, "Error",
				fmt.Sprintf("Error starting GUI: %v", err),
				walk.MsgBoxIconError)
			return
		}
		return
	}

	// Console mode
	if filePath == "" {
		fmt.Println("Please specify the driver path using -file flag")
		return
	}

	ext := filepath.Ext(filePath)
	if ext != ".sys" && ext != ".inf" {
		fmt.Println("File must be a driver (.sys) or driver information file (.inf)")
		return
	}

	cert, privateKey, err := findOrCreateCertificate()
	if err != nil {
		fmt.Printf("Certificate error: %v\n", err)
		return
	}

	err = signDriver(filePath, cert, privateKey)
	if err != nil {
		fmt.Printf("Error signing driver: %v\n", err)
		return
	}

	fmt.Println("Driver signed successfully")
}

type MyMainWindow struct {
	*walk.MainWindow
	label    *walk.TextLabel
	button   *walk.PushButton
	progress *walk.ProgressBar
	logView  *walk.TextEdit
}

func runGUI() error {
	mw := &MyMainWindow{}

	if err := (MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "GoDriverSigner",
		MinSize:  Size{800, 600},
		Layout:   VBox{},
		MenuItems: []MenuItem{
			Menu{
				Text: "&File",
				Items: []MenuItem{
					Action{
						Text: "Sign Driver...",
						OnTriggered: func() {
							mw.selectAndSignFile()
						},
					},
					Action{
						Text: "Verify Signature...",
						OnTriggered: func() {
							mw.verifySignature()
						},
					},
					Separator{},
					Action{
						Text: "Exit",
						OnTriggered: func() {
							mw.Close()
						},
					},
				},
			},
			Menu{
				Text: "&Certificate",
				Items: []MenuItem{
					Action{
						Text: "Create New Certificate",
						OnTriggered: func() {
							go func() {
								mw.logMessage("Creating new certificate...")
								mw.setProgress(20)
								
								cert, _, err := createAndInstallCertificate()
								mw.Synchronize(func() {
									if err != nil {
										mw.showError("Certificate Creation Error", err)
										mw.logMessage(fmt.Sprintf("Error: Failed to create certificate: %v", err))
									} else {
										mw.logMessage(fmt.Sprintf("Certificate created successfully\nSerial Number: %s", cert.SerialNumber))
										// Show certificate information
										certInfo := listExistingCertificates()
										mw.logMessage("\nCurrent certificate:\n" + certInfo)
									}
									mw.setProgress(100)
								})
							}()
						},
					},
					Action{
						Text: "Import Certificate...",
						OnTriggered: func() {
							mw.importCertificate()
						},
					},
					Action{
						Text: "Export Certificate...",
						OnTriggered: func() {
							mw.exportCertificate()
						},
					},
				},
			},
			Menu{
				Text: "&Tools",
				Items: []MenuItem{
					Action{
						Text: "Install Windows SDK",
						OnTriggered: func() {
							mw.installSDK()
						},
					},
					Action{
						Text: "Enable Windows Test Mode",
						OnTriggered: func() {
							mw.enableTestMode()
						},
					},
				},
			},
			Menu{
				Text: "&Help",
				Items: []MenuItem{
					Action{
						Text: "About",
						OnTriggered: func() {
							walk.MsgBox(mw, "About",
								"GoDriverSigner v1.0\n\nWindows Driver Signing Utility\n"+
									"Supports test certificate creation and driver signing\n\n"+
									"© 2024 GoDriverSigner",
								walk.MsgBoxIconInformation)
						},
					},
				},
			},
		},
		Children: []Widget{
			GroupBox{
				Title:  "Status",
				Layout: HBox{},
				Children: []Widget{
					TextLabel{
						AssignTo: &mw.label,
						Text:     "Ready",
						MinSize:  Size{300, 0},
					},
				},
			},
			GroupBox{
				Title:  "Actions",
				Layout: HBox{},
				Children: []Widget{
					PushButton{
						AssignTo: &mw.button,
						Text:     "Sign Driver",
						MinSize:  Size{150, 40},
						OnClicked: func() {
							mw.selectAndSignFile()
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Install Driver",
						MinSize: Size{150, 40},
						OnClicked: func() {
							mw.installDriver()
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Uninstall Driver",
						MinSize: Size{150, 40},
						OnClicked: func() {
							mw.uninstallDriver()
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Create Certificate",
						MinSize: Size{150, 40},
						OnClicked: func() {
							go func() {
								mw.logMessage("Creating new certificate...")
								mw.setProgress(20)
								
								cert, _, err := createAndInstallCertificate()
								mw.Synchronize(func() {
									if err != nil {
										mw.showError("Certificate Creation Error", err)
										mw.logMessage(fmt.Sprintf("Error: Failed to create certificate: %v", err))
									} else {
										mw.logMessage(fmt.Sprintf("Certificate created successfully\nSerial Number: %s", cert.SerialNumber))
										// Show certificate information
										certInfo := listExistingCertificates()
										mw.logMessage("\nCurrent certificate:\n" + certInfo)
									}
									mw.setProgress(100)
								})
							}()
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Show Certificate",
						MinSize: Size{150, 40},
						OnClicked: func() {
							certInfo := listExistingCertificates()
							if certInfo != "" {
								mw.logMessage("\nCurrent certificate:\n" + certInfo)
							} else {
								mw.logMessage("No certificates found")
							}
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Delete All Certificates",
						MinSize: Size{150, 40},
						OnClicked: func() {
							if walk.MsgBox(mw, "Warning",
								"Are you sure you want to delete all GoDriverSigner certificates?",
								walk.MsgBoxYesNo|walk.MsgBoxIconWarning) == walk.DlgCmdYes {
								go func() {
									mw.logMessage("Deleting all certificates...")
									mw.setProgress(20)
									
									err := deleteAllCertificates()
									mw.Synchronize(func() {
										if err != nil {
											mw.showError("Certificate Deletion Error", err)
											mw.logMessage(fmt.Sprintf("Error: Failed to delete certificates: %v", err))
										} else {
											walk.MsgBox(mw, "Success", 
												"All certificates deleted successfully",
												walk.MsgBoxIconInformation)
											mw.logMessage("All certificates deleted successfully")
										}
										mw.setProgress(100)
									})
								}()
							}
						},
					},
					HSpacer{Size: 10},
					PushButton{
						Text:    "Check Certificate",
						MinSize: Size{150, 40},
						OnClicked: func() {
							go func() {
								mw.logMessage("Checking certificate installation...")
								mw.setProgress(20)
								cert, _, err := findExistingCertificate()
								if err != nil {
									mw.Synchronize(func() {
										mw.showError("Error", fmt.Errorf("certificate not found: %v", err))
										mw.logMessage("Error: Certificate not found")
										mw.setProgress(100)
									})
									return
								}
								
								err = checkCertificateInstallation(cert)
								mw.Synchronize(func() {
									if err != nil {
										mw.showError("Error", fmt.Errorf("certificate installation issue: %v", err))
										mw.logMessage("Error: Certificate not installed correctly")
									} else {
										walk.MsgBox(mw, "Success", 
											"Certificate is properly installed in the system",
											walk.MsgBoxIconInformation)
										mw.logMessage("Certificate verified successfully")
									}
									mw.setProgress(100)
								})
							}()
						},
					},
				},
			},
			GroupBox{
				Title:  "Progress",
				Layout: HBox{},
				Children: []Widget{
					ProgressBar{
						AssignTo: &mw.progress,
						MinSize:  Size{0, 20},
						MaxValue: 100,
					},
				},
			},
			GroupBox{
				Title:  "Log",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{
						AssignTo: &mw.logView,
						ReadOnly: true,
						VScroll:  true,
						MinSize:  Size{0, 200},
					},
				},
			},
		},
	}.Create()); err != nil {
		return err
	}

	// Add window close handler
	mw.MainWindow.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		os.Exit(0) // Force terminate all goroutines when window is closed
	})

	// Center the window
	bounds := mw.Bounds()
	bounds.X = int((win.GetSystemMetrics(win.SM_CXSCREEN) - int32(bounds.Width)) / 2)
	bounds.Y = int((win.GetSystemMetrics(win.SM_CYSCREEN) - int32(bounds.Height)) / 2)
	mw.SetBounds(bounds)

	mw.logMessage("Program started")
	mw.Run()
	return nil
}

func (mw *MyMainWindow) logMessage(message string) {
	timestamp := time.Now().Format("15:04:05")
	currentText := mw.logView.Text()
	if currentText != "" && !strings.HasSuffix(currentText, "\r\n") {
		mw.logView.SetText(currentText + "\r\n")
	}
	mw.logView.AppendText(fmt.Sprintf("[%s] %s\r\n", timestamp, message))
	// Scroll to last line
	mw.logView.SendMessage(win.EM_SCROLLCARET, 0, 0)
}

func (mw *MyMainWindow) verifySignature() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select file to verify"
	dlg.Filter = "Drivers (*.sys;*.inf)|*.sys;*.inf"

	if ok, err := dlg.ShowOpen(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	mw.logMessage(fmt.Sprintf("Verifying signature of file: %s", dlg.FilePath))
	mw.setProgress(50)

	go func() {
		cmd := exec.Command("signtool", "verify", "/pa", dlg.FilePath)
		output, err := cmd.CombinedOutput()

		mw.Synchronize(func() {
			if err != nil {
				mw.showError("Invalid signature", fmt.Errorf("%s", output))
				mw.logMessage("Error: Invalid signature")
			} else {
				walk.MsgBox(mw, "Success", "Signature is valid", walk.MsgBoxIconInformation)
				mw.logMessage("Signature verified successfully")
			}
			mw.setProgress(100)
		})
	}()
}

func (mw *MyMainWindow) importCertificate() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select certificate"
	dlg.Filter = "Certificates (*.pfx;*.p12)|*.pfx;*.p12"

	if ok, err := dlg.ShowOpen(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	mw.logMessage(fmt.Sprintf("Importing certificate: %s", dlg.FilePath))
	mw.setProgress(30)

	// TODO: Add PFX password dialog
	// TODO: Implement certificate import
}

func (mw *MyMainWindow) exportCertificate() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Save certificate as"
	dlg.Filter = "PEM Certificate (*.pem)|*.pem|DER Certificate (*.der)|*.der|PFX Certificate (*.pfx)|*.pfx"

	if ok, err := dlg.ShowSave(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	mw.logMessage(fmt.Sprintf("Exporting certificate: %s", dlg.FilePath))
	mw.setProgress(40)

	// TODO: Implement certificate export in selected format
}

func (mw *MyMainWindow) installSDK() {
	if response := walk.MsgBox(mw, "Install SDK",
		"Windows SDK download and installation will begin. Continue?",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion); response == walk.DlgCmdNo {
		return
	}

	mw.logMessage("Starting Windows SDK installation...")
	mw.setProgress(10)

	go func() {
		err := installWindowsSDK()
		
		mw.Synchronize(func() {
			if err != nil {
				mw.showError("SDK Installation Error", err)
				mw.logMessage("Error: SDK installation failed")
			} else {
				walk.MsgBox(mw, "Success", "Windows SDK installed successfully", walk.MsgBoxIconInformation)
				mw.logMessage("Windows SDK installed successfully")
			}
			mw.setProgress(100)
		})
	}()
}

func (mw *MyMainWindow) enableTestMode() {
	if response := walk.MsgBox(mw, "Test Mode",
		"Enable Windows test mode? System restart required.",
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning); response == walk.DlgCmdNo {
		return
	}

	mw.logMessage("Enabling Windows test mode...")
	mw.setProgress(50)

	go func() {
		cmd := exec.Command("bcdedit", "/set", "testsigning", "on")
		err := cmd.Run()

		mw.Synchronize(func() {
			if err != nil {
				mw.showError("Error enabling test mode", err)
				mw.logMessage("Error: Failed to enable test mode")
			} else {
				if walk.MsgBox(mw, "Success",
					"Test mode enabled. System restart required. Restart now?",
					walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
					exec.Command("shutdown", "/r", "/t", "0").Run()
				}
				mw.logMessage("Windows test mode enabled")
			}
			mw.setProgress(100)
		})
	}()
}

func (mw *MyMainWindow) showError(title string, err error) {
	walk.MsgBox(mw, title, err.Error(), walk.MsgBoxIconError)
}

func (mw *MyMainWindow) setProgress(value int) {
	mw.progress.SetValue(value)
}

func (mw *MyMainWindow) selectAndSignFile() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select driver"
	dlg.Filter = "Drivers (*.sys;*.inf)|*.sys;*.inf"

	if ok, err := dlg.ShowOpen(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	filePath := dlg.FilePath
	mw.button.SetEnabled(false)
	mw.label.SetText(fmt.Sprintf("Signing %s...", filepath.Base(filePath)))
	mw.logMessage(fmt.Sprintf("Starting file signing: %s", filePath))
	mw.setProgress(20)

	go func() {
		var result string
		var success bool

		cert, key, err := findOrCreateCertificate()
		if err != nil {
			result = fmt.Sprintf("Certificate error: %v", err)
			success = false
		} else {
			mw.Synchronize(func() {
				mw.setProgress(50)
				mw.logMessage("Certificate obtained, signing in progress...")
			})

			err = signDriver(filePath, cert, key)
			if err != nil {
				if err.Error() == "driver is already signed" {
					result = fmt.Sprintf("Driver %s is already signed", filepath.Base(filePath))
					success = true
				} else {
					result = fmt.Sprintf("Error signing driver: %v", err)
					success = false
				}
			} else {
				result = fmt.Sprintf("Driver %s signed successfully", filepath.Base(filePath))
				success = true
			}
		}

		mw.Synchronize(func() {
			if success {
				walk.MsgBox(mw, "Information", result, walk.MsgBoxIconInformation)
				mw.logMessage(result)
			} else {
				walk.MsgBox(mw, "Error", result, walk.MsgBoxIconError)
				mw.logMessage("Error: " + result)
			}
			mw.label.SetText("Ready")
			mw.button.SetEnabled(true)
			mw.setProgress(100)
		})
	}()
}

func (mw *MyMainWindow) installDriver() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select driver to install"
	dlg.Filter = "Drivers (*.inf)|*.inf"

	if ok, err := dlg.ShowOpen(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	mw.logMessage(fmt.Sprintf("Installing driver: %s", dlg.FilePath))
	mw.setProgress(20)

	go func() {
		// Sign driver before installation
		cert, key, err := findOrCreateCertificate()
		if err != nil {
			mw.Synchronize(func() {
				mw.showError("Certificate Error", err)
				mw.setProgress(100)
			})
			return
		}

		if err := signDriver(dlg.FilePath, cert, key); err != nil {
			mw.Synchronize(func() {
				mw.showError("Signing Error", err)
				mw.setProgress(100)
			})
			return
		}

		mw.Synchronize(func() {
			mw.setProgress(50)
			mw.logMessage("Driver signed, proceeding with installation...")
		})

		// Install driver
		cmd := exec.Command("pnputil", "/add-driver", dlg.FilePath, "/install")
		output, err := cmd.CombinedOutput()

		mw.Synchronize(func() {
			if err != nil {
				mw.showError("Installation Error", fmt.Errorf("error: %v\nOutput: %s", err, output))
				mw.logMessage("Error installing driver")
			} else {
				walk.MsgBox(mw, "Success", "Driver installed successfully", walk.MsgBoxIconInformation)
				mw.logMessage("Driver installed successfully")
			}
			mw.setProgress(100)
		})
	}()
}

func (mw *MyMainWindow) uninstallDriver() {
	dlg := new(walk.FileDialog)
	dlg.Title = "Select driver to uninstall"
	dlg.Filter = "Drivers (*.inf)|*.inf"

	if ok, err := dlg.ShowOpen(mw); err != nil {
		mw.showError("Error opening dialog", err)
		return
	} else if !ok {
		return
	}

	mw.logMessage(fmt.Sprintf("Uninstalling driver: %s", dlg.FilePath))
	mw.setProgress(20)

	go func() {
		// Get driver name from INF file
		driverName := filepath.Base(dlg.FilePath)
		driverName = strings.TrimSuffix(driverName, ".inf")

		// Uninstall driver
		cmd := exec.Command("pnputil", "/delete-driver", driverName, "/uninstall", "/force")
		output, err := cmd.CombinedOutput()

		mw.Synchronize(func() {
			if err != nil {
				mw.showError("Uninstall Error", fmt.Errorf("error: %v\nOutput: %s", err, output))
				mw.logMessage("Error uninstalling driver")
			} else {
				walk.MsgBox(mw, "Success", "Driver uninstalled successfully", walk.MsgBoxIconInformation)
				mw.logMessage("Driver uninstalled successfully")
			}
			mw.setProgress(100)
		})
	}()
}

func findOrCreateCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Try to find existing certificate
	cert, key, err := findExistingCertificate()
	if err == nil {
		return cert, key, nil
	}

	// If no certificate found, warn the user
	if walk.MsgBox(nil, "Certificate Not Found",
		"No signing certificate found. Would you like to create a new one?",
		walk.MsgBoxYesNo|walk.MsgBoxIconWarning) == walk.DlgCmdNo {
		return nil, nil, fmt.Errorf("certificate required for signing")
	}

	// Create new certificate
	return createAndInstallCertificate()
}

func findExistingCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	certPath := filepath.Join(os.Getenv("USERPROFILE"), certFileName)
	keyPath := filepath.Join(os.Getenv("USERPROFILE"), keyFileName)

	// Check if files exist
	if _, err := os.Stat(certPath); err != nil {
		return nil, nil, err
	}
	if _, err := os.Stat(keyPath); err != nil {
		return nil, nil, err
	}

	// Read certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	// Read private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func checkCertificateInstallation(cert *x509.Certificate) error {
	// Check certificate presence in ROOT store by its serial number using PowerShell
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(
		`Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.SerialNumber -eq "%s"}`, 
		cert.SerialNumber.Text(16)))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error checking certificate: %v\nOutput: %s", err, string(output))
	}

	if len(output) == 0 {
		return fmt.Errorf("certificate not found in system store")
	}

	return nil
}

func installCertificate(certBytes []byte, privateKey *rsa.PrivateKey) error {
	// Save certificate to temporary file
	tempDir := os.TempDir()
	certPath := filepath.Join(tempDir, "temp_cert.cer")
	
	// Save certificate in DER format
	if err := os.WriteFile(certPath, certBytes, 0600); err != nil {
		return fmt.Errorf("error saving certificate: %v", err)
	}
	defer os.Remove(certPath)

	// Install certificate using PowerShell
	psCmd := fmt.Sprintf(`
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("%s")
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("ROOT", "LocalMachine")
		$store.Open("ReadWrite")
		$store.Add($cert)
		$store.Close()
	`, certPath)

	cmd := exec.Command("powershell", "-Command", psCmd)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error installing certificate: %v\nOutput: %s", err, string(output))
	}

	// Save private key
	keyPath := filepath.Join(os.Getenv("USERPROFILE"), keyFileName)
	keyOut := new(bytes.Buffer)
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	
	if err := os.WriteFile(keyPath, keyOut.Bytes(), 0600); err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}

	// Verify certificate installation using PowerShell
	thumbprint := fmt.Sprintf("%x", sha1.Sum(certBytes))
	checkCmd := exec.Command("powershell", "-Command", fmt.Sprintf(
		`$cert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "%s"}; if ($cert) { Write-Host "Certificate installed successfully" } else { throw "Certificate not found in store" }`,
		thumbprint))
	
	if output, err := checkCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("certificate installation verification failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

func createAndInstallCertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	// Delete old certificates before creating new one
	if err := deleteAllCertificates(); err != nil {
		return nil, nil, fmt.Errorf("error deleting old certificates: %v", err)
	}

	// Generate random 8-byte name
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, nil, fmt.Errorf("error generating random name: %v", err)
	}
	name := fmt.Sprintf("GoDriverSigner_%x", randomBytes)

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"GoDriverSigner"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	// Save certificate
	if err := installCertificate(certBytes, privateKey); err != nil {
		return nil, nil, fmt.Errorf("error installing certificate: %v", err)
	}

	return cert, privateKey, nil
}

func checkAdminRights() (bool, error) {
	var token windows.Token
	h := windows.CurrentProcess()
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, fmt.Errorf("error opening process token: %v", err)
	}
	defer token.Close()

	// Get token information
	var elevation uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenElevation, (*byte)(unsafe.Pointer(&elevation)), uint32(unsafe.Sizeof(elevation)), &returnedLen)
	if err != nil {
		return false, fmt.Errorf("error getting token information: %v", err)
	}

	return elevation != 0, nil
}

func checkAndInstallRequirements() error {
	// Check for certutil
	if !checkCommand("certutil") {
		return fmt.Errorf("certutil not found. It should be installed with Windows")
	}

	// Check for signtool
	signtoolPath := findSignTool()
	if signtoolPath == "" {
		fmt.Println("SignTool not found. Trying to install Windows SDK...")
		if err := installWindowsSDK(); err != nil {
			return fmt.Errorf("error installing Windows SDK: %v", err)
		}
		
		// Recheck after installation
		signtoolPath = findSignTool()
		if signtoolPath == "" {
			return fmt.Errorf("SignTool not found even after installing Windows SDK")
		}
	}

	return nil
}

func checkCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func findSignTool() string {
	// Search in standard Windows SDK installation locations
	commonPaths := []string{
		"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\*\\x64\\signtool.exe",
		"C:\\Program Files (x86)\\Windows Kits\\10\\App Certification Kit\\signtool.exe",
		"C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v*\\bin\\signtool.exe",
	}

	for _, pattern := range commonPaths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			// Return newest version
			return matches[len(matches)-1]
		}
	}

	return ""
}

func installWindowsSDK() error {
	fmt.Println("Checking for running setup.exe...")
	
	// Check if installer is already running
	processes, err := exec.Command("tasklist", "/FI", "IMAGENAME eq winsdksetup.exe", "/FO", "CSV", "/NH").Output()
	if err == nil && len(processes) > 0 && strings.Contains(string(processes), "winsdksetup.exe") {
		// Ask user if they want to wait for current installation to finish
		if response := walk.MsgBox(nil, "Setup.exe is running",
			"Detected running setup.exe process.\n\n"+
			"Click 'Yes' to wait for the current setup to finish,\n"+
			"or 'No' to cancel the operation.",
			walk.MsgBoxYesNo|walk.MsgBoxIconWarning); response == walk.DlgCmdNo {
			return fmt.Errorf("operation cancelled by user")
		}

		fmt.Println("Waiting for previous setup to finish...")
		for i := 0; i < 60; i++ { // Maximum wait time - 5 minutes
			time.Sleep(5 * time.Second)
			checkProcesses, _ := exec.Command("tasklist", "/FI", "IMAGENAME eq winsdksetup.exe", "/FO", "CSV", "/NH").Output()
			if !strings.Contains(string(checkProcesses), "winsdksetup.exe") {
				fmt.Println("Previous setup finished")
				break
			}
			if i == 59 {
				return fmt.Errorf("timeout waiting for previous setup to finish")
			}
		}
	}

	fmt.Println("Downloading Windows SDK...")
	
	// Create temporary directory
	tempDir := os.TempDir()
	installerPath := filepath.Join(tempDir, "winsdksetup.exe")

	// Remove old installer if exists
	os.Remove(installerPath)

	fmt.Println("Starting SDK download...")

	// Download installer with progress display
	client := &http.Client{}
	req, err := http.NewRequest("GET", windowsSDKUrl, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error downloading Windows SDK: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error downloading SDK: status %d", resp.StatusCode)
	}

	out, err := os.Create(installerPath)
	if err != nil {
		return fmt.Errorf("error creating setup.exe file: %v", err)
	}
	defer out.Close()

	fmt.Println("Saving setup.exe...")
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("error saving setup.exe: %v", err)
	}

	// Close file before running
	out.Close()

	fmt.Println("Starting SDK installation...")
	fmt.Println("Please follow the setup instructions...")

	// Run installer in interactive mode
	cmd := exec.Command("cmd", "/C", "start", "/wait", installerPath)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Run(); err != nil {
		// Check if process was cancelled by user
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1602 { // User cancellation code
				return fmt.Errorf("setup cancelled by user")
			}
		}
		return fmt.Errorf("error installing Windows SDK: %v", err)
	}

	fmt.Println("Waiting for setup to finish...")
	time.Sleep(5 * time.Second)

	// Remove installer
	os.Remove(installerPath)

	// Verify successful installation
	if signtoolPath := findSignTool(); signtoolPath == "" {
		return fmt.Errorf("setup completed, but signtool.exe not found. Possible system reboot required")
	}

	fmt.Println("Windows SDK successfully installed")
	return nil
}

func checkDriverInstallation(driverPath string) error {
	// Get driver name from file path
	driverName := filepath.Base(driverPath)
	driverName = strings.TrimSuffix(driverName, filepath.Ext(driverName))

	// Check driver presence in system using PowerShell
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf(`Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -eq "%s"}`, driverName))
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		return fmt.Errorf("error checking driver installation: %v", err)
	}

	if len(output) == 0 {
		return fmt.Errorf("driver not found in the system")
	}

	// Check driver status
	cmd = exec.Command("powershell", "-Command", fmt.Sprintf(`(Get-WmiObject Win32_SystemDriver | Where-Object {$_.Name -eq "%s"}).State`, driverName))
	output, err = cmd.CombinedOutput()
	
	if err != nil {
		return fmt.Errorf("error checking driver status: %v", err)
	}

	status := strings.TrimSpace(string(output))
	if status != "Running" && status != "Stopped" {
		return fmt.Errorf("driver in incorrect state: %s", status)
	}

	return nil
}

func signDriver(driverPath string, cert *x509.Certificate, privateKey *rsa.PrivateKey) error {
	// Check if driver is already signed
	verifyCmd := exec.Command("signtool", "verify", "/pa", driverPath)
	if err := verifyCmd.Run(); err == nil {
		return fmt.Errorf("driver is already signed")
	}

	// Check if certificate exists
	if cert == nil || privateKey == nil {
		return fmt.Errorf("no certificate found. Please create or import a certificate first")
	}

	tempDir := os.TempDir()
	certPath := filepath.Join(tempDir, "temp_cert.cer")
	pfxPath := filepath.Join(tempDir, "temp_cert.pfx")
	
	// Save certificate in DER format
	if err := os.WriteFile(certPath, cert.Raw, 0600); err != nil {
		return fmt.Errorf("error saving certificate: %v", err)
	}
	defer os.Remove(certPath)

	// Create PFX
	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, nil, "")
	if err != nil {
		return fmt.Errorf("error creating PFX: %v", err)
	}
	
	if err := os.WriteFile(pfxPath, pfxData, 0600); err != nil {
		return fmt.Errorf("error saving PFX: %v", err)
	}
	defer os.Remove(pfxPath)

	// Find signtool path
	signtoolPath := findSignTool()
	if signtoolPath == "" {
		return fmt.Errorf("signtool.exe not found")
	}

	// Install certificate in store
	installCmd := exec.Command("certutil", "-f", "-addstore", "Root", certPath)
	if output, err := installCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error installing certificate: %v\nOutput: %s", err, string(output))
	}

	// Sign the driver
	cmd := exec.Command(signtoolPath,
		"sign",
		"/v",
		"/f", pfxPath,
		"/p", "",  // Empty PFX password
		"/tr", "http://timestamp.digicert.com",
		"/td", "sha256",
		"/fd", "sha256",
		driverPath)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error signing driver: %v\nOutput: %s", err, string(output))
	}

	// Wait for file system to update
	time.Sleep(2 * time.Second)

	// Verify the signature
	verifyCmd := exec.Command(signtoolPath,
		"verify",
		"/pa",
		"/v",
		driverPath)
	
	verifyOutput, err := verifyCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("signature verification failed: %v\nOutput: %s", err, string(verifyOutput))
	}

	return nil
}

func listExistingCertificates() string {
	cmd := exec.Command("powershell", "-Command", "Get-ChildItem -Path Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -like '*GoDriverSigner*'} | ForEach-Object { 'Certificate: ' + $_.Subject + [Environment]::NewLine + 'Serial Number: ' + $_.SerialNumber + [Environment]::NewLine + 'Valid From: ' + $_.NotBefore + [Environment]::NewLine + 'Valid To: ' + $_.NotAfter + [Environment]::NewLine + 'Thumbprint: ' + $_.Thumbprint + [Environment]::NewLine + '-------------------' }")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error listing certificates: %v", err)
	}
	return string(output)
}

func deleteAllCertificates() error {
	cmd := exec.Command("powershell", "-Command", `
		Get-ChildItem -Path Cert:\LocalMachine\Root | 
		Where-Object {$_.Subject -like '*GoDriverSigner*'} | 
		ForEach-Object {
			$thumbprint = $_.Thumbprint
			Remove-Item -Path "Cert:\LocalMachine\Root\$thumbprint" -DeleteKey
		}`)
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting certificates: %v\nOutput: %s", err, string(output))
	}
	return nil
} 