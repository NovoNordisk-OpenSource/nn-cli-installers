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
├── /push-installers.ps1    # Script to publish installers to public repo
├── /test-installer.sh      # Installer test script
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

### Manual Publishing

To manually publish installer scripts to the public repository:

```powershell
# Dry run to see what would be published
./push-installers.ps1 -DryRun

# Publish with existing git credentials
./push-installers.ps1

# Publish with a Personal Access Token
./push-installers.ps1 -PAT "ghp_xxxxxxxxxxxx"
```

The `push-installers.ps1` script will:
1. Clone the public installer repository to a temporary directory
2. Copy the current installer scripts from this directory
3. Commit and push any changes to the main branch
4. Clean up the temporary directory

### Requirements for Publishing

- Git must be installed and available in PATH
- A GitHub account with **write access** to the [NovoNordisk-OpenSource/nn-cli-installers](https://github.com/NovoNordisk-OpenSource/nn-cli-installers) repository
- Either:
  - Git credentials configured (`git config --global credential.helper manager`)
  - OR a GitHub Personal Access Token (PAT) with:
    - `repo` scope
    - Associated with an account that has push permissions to the public repository

### Testing Authentication

Before publishing, you can test if your PAT has the proper permissions:

```powershell
# Test if PAT has proper permissions
./push-installers.ps1 -TestAuth -PAT "ghp_xxxxxxxxxxxx"
```

### Troubleshooting

If you get a "Permission denied" error:
1. Verify your GitHub account has write access to the public repository
2. Create a new PAT at https://github.com/settings/tokens with `repo` scope
3. Test your PAT using the `-TestAuth` parameter
4. Contact the repository administrator if you need access
