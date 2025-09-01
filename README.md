# installers

Cross-platform installation scripts for NN CLI.

## Documentation

- **[Installation Guide](https://github.com/nn-gdai/nn-cli/blob/main/documentation/guide/docs/nncli/installers.md)** - Installation documentation
- **[Local Installation](https://github.com/nn-gdai/nn-cli/blob/main/documentation/guide/docs/nncli/local-installation.md)** - Development setup

## Directory Structure

```text
/installers/
├── /install.ps1            # Windows PowerShell installer
├── /install.sh             # Unix/Linux bash installer
├── /CLAUDE.md              # Claude-specific guidelines
└── /README.md              # This file
```

## Installation Methods

| Platform        | Script        | Command                                                |
| --------------- | ------------- | ------------------------------------------------------ |
| Windows         | `install.ps1` | `powershell -ExecutionPolicy Bypass -File install.ps1` |
| Linux/macOS     | `install.sh`  | `bash install.sh`                                      |
| PowerShell Core | `install.ps1` | `pwsh install.ps1`                                     |

## Quick Install

```bash
# Unix/Linux/macOS
curl -sSL https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.sh | bash

# Windows PowerShell
iwr -useb https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.ps1 | iex
```

## Features

- Automatic platform detection
- Binary download and verification
- PATH configuration
- Extension support

## Publishing Installers

The installer scripts are automatically published to the public repository [NovoNordisk-OpenSource/nn-cli-installers](https://github.com/NovoNordisk-OpenSource/nn-cli-installers) via GitHub Actions when changes are pushed to the main branch.
