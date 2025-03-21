# LNK_Drop Tool

## Overview
LNK_Drop is a PowerShell tool designed for security professionals and penetration testers to create customized shortcut (LNK) files for educational purposes and authorized security testing. This tool demonstrates various Living-Off-The-Land Binary (LOLBIN) techniques and payload delivery methods.

## Disclaimer
This tool is intended **ONLY** for:
- Authorized security testing
- Educational purposes
- Cybersecurity research
- Demonstration of attacker methodologies

Unauthorized use against systems without explicit permission is illegal and unethical.

## Features
- Multiple LOLBIN chain options for payload delivery
- Reflective DLL injection capabilities
- Network-based payload delivery options
- Donut integration for in-memory execution
- Anti-analysis techniques
- Polymorphic code generation
- Multiple icon customization options

## Requirements
- Windows operating system
- PowerShell 5.1 or higher
- Donut binary (automatically downloaded if not present)

## Usage

```powershell
.\lnk_drop.ps1 -PayloadPath <path_to_your_payload>
```

### Parameters
- **PayloadPath** (Mandatory): Path to the payload file (.ps1 or .exe)

### Delivery Methods
1. **wmic + mshta + regsvr32 (Extreme stealth)**: Chain of LOLBINs for enhanced evasion
2. **rundll32 + certutil + mshta (Memory injection)**: Leverages memory injection techniques
3. **mshta + wmic + rundll32 (Fragmented chain)**: Uses a fragmented execution chain
4. **Reflective DLL (In-memory DLL injection with AES)**: In-memory execution with encryption
5. **Network Delivery (C2 fetch with AES-encrypted DLL)**: Remote payload retrieval
6. **Create Donut DLL/PS1 (Generate for later use)**: Generate payloads for future use

### Icon Options
- Microsoft Edge PDF Icon
- Adobe Acrobat PDF Icon
- Generic Windows PDF Icon
- Microsoft Word (.doc) Icon
- Notepad (.txt) Icon
- PNG Image Icon
- JPEG Image Icon

## Technical Details

### Encryption and Obfuscation
- XOR encryption for payload protection
- AES encryption for sensitive data
- Polymorphic code generation to enhance evasion
- Anti-analysis checks

### Payload Support
- PowerShell scripts (.ps1)
- Executable files (.exe) when using DLL or network delivery

## Example
```powershell
# Create a LNK with a PowerShell payload
.\lnk_drop.ps1 -PayloadPath C:\payloads\test_script.ps1

# Select delivery method from the interactive menu
# Choose icon type
# Enter custom LNK name or use default
```

## Notes
- The tool will automatically download the Donut binary if not found
- Created LNK files will be placed on the desktop by default
- For network delivery, ensure your C2 server is properly configured
