# ⚛️ React2Shell (CVE-2025-55182)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Vulnerability](https://img.shields.io/badge/CVE-2025--55182-Critical-red?style=for-the-badge)

**Advanced Exploitation Toolkit for Next.js Server Actions (CVE-2025-55182).**

React2Shell is a powerful, interactive shell wrapper designed to exploit the React2Shell vulnerability. It goes beyond simple RCE by providing command history, file transfer capabilities, and automated privilege escalation strategies.

---

## 🚀 Features

- **Single-File Executable**: Consolidates exploit logic and shell interface into one script. Zero external dependencies.
- **Interactive Shell**: Full pseudo-terminal experience with command history.
- **Auto-Root Escalation**: Built-in pipe injection strategy `base64 | sudo -i`) to bypass shell restrictions and escalate to root instantly.
- **File Operations**:
  - `.download <remote> [local]`: Reliable binary-safe file download using base64 encoding.
  - `.save`: Save command output to local evidence files.
- **Base64 Evasion**: Automatically encodes payloads to bypass basic WAF filters and shell quoting issues.

## Screenshots

<img width="2456" height="1448" alt="1" src="https://github.com/user-attachments/assets/740b882a-709f-4b6c-b2aa-5dd142309af4" />
<img width="1566" height="592" alt="2" src="https://github.com/user-attachments/assets/e73ca3de-3a3b-4d4b-bc9f-d81e15da5b09" />

# React2Shell-Scanner

## 🛠️ Installation

```bash
git clone https://github.com/ula7i921011/React2Shell-Scanner.git
cd React2Shell-Scanner
pip install requests
```

## 💻 Usage

### Basic Usage

**Linux/macOS:**
```bash
python3 react2shell.py -u https://target-nextjs-site.com/
```

**Windows:**
```bash
python react2shell.py -u https://target-nextjs-site.com/
```

### Advanced Usage

Run with verified root persistence strategy detection:

**Linux/macOS:**
```bash
python3 react2shell.py -u https://target.com/
```

**Windows:**
```bash
python react2shell.py -u https://target.com/
```

if you use Windows please replace python3 -> python in command

### Advanced Usage

Run with verified root persistence strategy detection:

```bash
python react2shell.py -u https://target.com/
```

## 🎮 Command Interface

Once inside the shell:

| Command | Description |
|:---|:---|
| `.root` | Toggle **Root Mode** (Wraps commands in `sudo -i`) |
| `.download <file>` | Download a file from the remote server |
| `.save` | Save the last command's output to a file |
| `.exit` | Exit the shell |

### Example Session

```bash
ubuntu@target:~$ id
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)...

ubuntu@target:~$ .root
[*] Root mode ENABLED

root@target:~$ id
uid=0(root) gid=0(root) groups=0(root)
```

## ⚠️ Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY.**

This tool is intended for security research and authorization testing only. The authors are not responsible for any misuse or damage caused by this tool. Do not scan or exploit targets you do not have explicit permission to test.

---

*Developed for ethical penetration testing and red teaming operations.*