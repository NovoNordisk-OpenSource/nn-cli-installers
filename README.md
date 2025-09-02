# installers

Cross-platform installation scripts for NN CLI.

## Quick Install

### Linux/MacOS

```bash
curl -sSL https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.sh | bash
```

### Windows/Linux/MacOS PowerShell

```powershell
iwr -useb https://raw.githubusercontent.com/NovoNordisk-OpenSource/nn-cli-installers/refs/heads/main/install.ps1 | iex
```

## Documentation

- **[NN CLI Installation Guide](https://github.com/nn-gdai/nn-cli/blob/main/documentation/guide/docs/nncli/installers.md)**
- **[NN CLI Development Setup](https://github.com/nn-gdai/nn-cli/blob/main/documentation/guide/docs/nncli/local-installation.md)**

## Directory Structure

```text
/installers/
├── /install.ps1            # Windows/Linux/MacOS PowerShell installer
├── /install.sh             # Linux/MacOS bash installer
├── /CLAUDE.md              # Claude-specific guidelines
└── /README.md              # This file
```

## Installation Methods

| Platform            | Script        | Command            |
| ------------------- | ------------- | ------------------ |
| Linux/macOS         | `install.sh`  | `bash install.sh`  |
| Windows/Linux/macOS | `install.ps1` | `pwsh install.ps1` |

## Features

- Automatic platform detection
- Binary download and verification
- PATH configuration
- Extension support

## Publishing Installers

The installer scripts are automatically published to the public repository [NovoNordisk-OpenSource/nn-cli-installers](https://github.com/NovoNordisk-OpenSource/nn-cli-installers) via GitHub Actions when changes are pushed to the main branch.
