# GoDriverSigner

A Windows utility for signing and managing driver signatures with test certificates.

## Features

- Driver signing with test certificates
- Certificate creation and management
- Driver installation and uninstallation
- GUI and command-line interfaces
- Windows SDK auto-installation
- Windows test mode support
- Automatic recovery from failures

## Installation

1. Install Go 1.16 or later
2. Install Windows SDK (will be installed automatically if not present)
3. Clone the repository:
```bash
git clone https://github.com/mr-kotik/GoDriverSigner.git
cd GoDriverSigner
```
4. Install dependencies and build:
```bash
go mod download
go build -ldflags="-H windowsgui"
```

## Usage

### GUI Mode

The easiest way to use GoDriverSigner is through its graphical interface:

1. Run `goDriverSigner.exe` (requires administrator rights)
2. Use the menu or drag-and-drop files to:
   - Sign drivers
   - Create/manage certificates
   - Install/uninstall drivers
   - Enable test mode
   - Verify signatures

### Command Line Mode

Sign a driver:
```bash
goDriverSigner.exe -file path_to_driver.sys
```

Sign multiple files:
```bash
goDriverSigner.exe -file "drivers/*.sys"
```

Verify signature:
```bash
goDriverSigner.exe -file driver.sys -verify
```

### Additional Features

Interactive mode:
```bash
goDriverSigner.exe -interactive
```

Force certificate recreation:
```bash
goDriverSigner.exe -file driver.sys -force
```

Import existing certificate:
```bash
goDriverSigner.exe -pfx certificate.pfx -pfx-password password
```

Export certificate:
```bash
goDriverSigner.exe -export pem  # Available formats: pem, der, pfx
```

Enable Windows test mode:
```bash
goDriverSigner.exe -test-mode
```

### Certificate Configuration

Set organization details:
```bash
goDriverSigner.exe -file driver.sys -org "My Company" -country US
```

### CI/CD Mode

For use in scripts:
```bash
goDriverSigner.exe -file driver.sys -ci
```

## Configuration

Settings are stored in `%USERPROFILE%\.goDriverSigner\config.json`:
- Certificate file paths
- Timestamp servers
- Security settings
- SDK parameters

## Logging

Logs are saved in `%USERPROFILE%\.goDriverSigner\logs\`:
- Detailed operation information
- Diagnostic information
- File signing history

## Troubleshooting

1. If the program reports lack of administrator rights:
   - Right-click and select "Run as administrator"

2. If Windows SDK installation fails:
   - Check internet connection
   - Use `-offline` flag for offline installation
   - Try manual SDK installation

3. If signing problems occur:
   - Use `-verbose` flag for detailed logging
   - Check the logs folder
   - Try recreating the certificate with `-force` flag

## Security Notes

- The certificate is installed in trusted root certification authorities
- Uses RSA-4096 for key generation
- Signing uses SHA-256 and timestamps
- Private key is stored encrypted
- Automatic certificate backup

## Important

- This tool is intended for test signing only
- Do not use test certificates in production
- Keep private keys secure
- Regular certificate rotation recommended

## Requirements

- Windows 10 or later
- Administrator rights
- .NET Framework 4.5 or later
- Internet connection for SDK download

## License

MIT License. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Support

For issues and feature requests, please use the GitHub issue tracker. 