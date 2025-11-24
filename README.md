# Chromium V20 Extractor
### Tool for understanding Chromium’s V10/V11/V20 password encryption on Windows

**chromium-v20-extractor** is an educational digital-forensics and security-research tool that demonstrates how modern Chromium-based browsers encrypt and protect saved logins.  
The project focuses on the **V20 App-Bound Encryption** introduced by Google to increase OS bound key security.

> ⚠️ **Strictly for educational use, research, cybersecurity training, and analysis of systems you personally own or have explicit written permission to test.**  
> Misuse may be illegal. The author is not responsible for misuse.

---

## 📘 Overview

Modern Chromium browsers (Chrome, Edge, Brave, Opera, Opera GX) use one of three encryption formats when storing passwords:

| Version | Encryption | Key Source |
|--------|------------|------------|
| **v10** | AES-GCM | Windows DPAPI |
| **v11** | AES-GCM | Windows DPAPI |
| **v20** | AES-GCM + App-Bound Key | OS-bound system key, validated under SYSTEM account |

- Extracting **DPAPI** V10/V11 keys  
- Extracting **APPB** V20 “App-Bound” keys  
- Decrypting the `Login Data` SQLite database entries  
- Exporting readable password results for analysis

---

## ✨ Features

- Support for Chrome, Brave, Edge, Opera & Opera GX  
- Full handling of V10/V11/V20 encrypted entries  
- SYSTEM-level decryption for App-Bound keys (via PyPsexec)  
- Automatic admin elevation  
- Read-only access to browser files (no modification)  
- Clean export of decrypted data in .txt files
  
---
