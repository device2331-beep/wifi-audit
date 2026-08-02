#!/usr/bin/env python3
"""
WiFi Network Security Audit Tool
Nijer WiFi network-er security check korar jonno
"""

import socket
import subprocess
import threading
import json
import urllib.request
import urllib.error
from datetime import datetime

RISKY_PORTS = {
    21: "FTP - Unencrypted file transfer, risky",
    22: "SSH - Remote access, weak password thakle risky",
    23: "Telnet - Unencrypted, very risky (avoid)",
    25: "SMTP - Mail server",
    53: "DNS",
    80: "HTTP - Web/admin panel, unencrypted",
    110: "POP3 - Unencrypted mail",
    139: "NetBIOS - File sharing, risky",
    443: "HTTPS - Web/admin panel, encrypted (safer)",
    445: "SMB - File sharing, high risk if open",
    3389: "RDP - Remote desktop, high risk if open",
    8080: "HTTP-alt - Often admin panel",
    8888: "Alt HTTP",
}

# Router admin panel gula check korar jonno common ports
ADMIN_PORTS = [80, 443, 8080, 8081, 7547]

# Shudhu common/default credential check (nijer router audit-er jonno)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("root", "root"),
    ("user", "user"),
]

results = []
lock = threading.Lock()
router_report = {}

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Chhoto block-letter font (5 ta row) - MEHIDI_BRO banner-er jonno
BANNER_FONT = {
    "M": ["#   #", "## ##", "# # #", "#   #", "#   #"],
    "E": ["#####", "#    ", "#### ", "#    ", "#####"],
    "H": ["#   #", "#   #", "#####", "#   #", "#   #"],
    "I": ["###", " # ", " # ", " # ", "###"],
    "D": ["#### ", "#   #", "#   #", "#   #", "#### "],
    "_": ["     ", "     ", "     ", "     ", "#####"],
    "B": ["#### ", "#   #", "#### ", "#   #", "#### "],
    "R": ["#### ", "#   #", "#### ", "#  # ", "#   #"],
    "O": [" ### ", "#   #", "#   #", "#   #", " ### "],
    " ": ["  ", "  ", "  ", "  ", "  "],
}


def print_banner(text="MEHIDI_BRO"):
    rows = ["" for _ in range(5)]
    for ch in text.upper():
        glyph = BANNER_FONT.get(ch, BANNER_FONT[" "])
        for i in range(5):
            rows[i] += glyph[i] + " "
    print(GREEN)
    for row in rows:
        print(row)
    print(RESET)


def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        subnet = ".".join(local_ip.split(".")[:3])
        return subnet, local_ip
    except Exception as e:
        print(f"[!] Local IP ber korte problem: {e}")
        return None, None


def get_default_gateway(subnet=None):
    """Kayekta method try kore default gateway ber korar cheshta"""

    # Method 1: /proc/net/route (root thakle kaj kore)
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) < 3:
                    continue
                iface, dest, gateway = fields[0], fields[1], fields[2]
                if dest == "00000000":
                    gw_hex = gateway
                    gw_bytes = [gw_hex[i:i + 2] for i in range(0, 8, 2)]
                    gw_ip = ".".join(str(int(b, 16)) for b in reversed(gw_bytes))
                    return gw_ip
    except Exception:
        pass

    # Method 2: `ip route` command (Termux-e sathe thake)
    try:
        result = subprocess.run(
            ["ip", "route"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
    except Exception:
        pass

    # Method 3: Fallback - subnet-er .1 ke gateway dhore neya
    # (Beshirvag home router-e .1 e gateway thake)
    if subnet:
        print("[*] Direct method kaj korenai, .1 ke gateway dhore checking korছি...")
        return f"{subnet}.1"

    return None


def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_ports(ip, ports=RISKY_PORTS.keys()):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass
    return open_ports


def audit_host(ip):
    if ping_host(ip):
        open_ports = scan_ports(ip)
        with lock:
            results.append({
                "ip": ip,
                "status": "alive",
                "open_ports": open_ports,
                "risky_ports": [
                    {"port": p, "desc": RISKY_PORTS.get(p, "Unknown")}
                    for p in open_ports
                ]
            })
        if open_ports:
            print(f"{RED}[+] {ip} -> Open ports: {open_ports}{RESET}")
        else:
            print(f"{GREEN}[+] {ip} -> Live, but no risky ports open{RESET}")


def scan_network(subnet):
    threads = []
    print(f"{CYAN}[*] Scanning {subnet}.1 - {subnet}.254 ...{RESET}")
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        t = threading.Thread(target=audit_host, args=(ip,))
        threads.append(t)
        t.start()
        if len(threads) >= 50:
            for t in threads:
                t.join()
            threads = []
    for t in threads:
        t.join()


def check_admin_panel(gateway_ip):
    """Router-er admin panel open ache kina check kore, r default creds try kore"""
    print(f"\n{CYAN}[*] Router admin panel check korছি ({gateway_ip}) ...{RESET}")
    panel_info = {
        "gateway_ip": gateway_ip,
        "open_admin_ports": [],
        "weak_default_creds": False,
        "warning": []
    }

    for port in ADMIN_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.7)
            result = sock.connect_ex((gateway_ip, port))
            sock.close()
            if result == 0:
                panel_info["open_admin_ports"].append(port)
        except Exception:
            pass

    if not panel_info["open_admin_ports"]:
        print(f"{GREEN}[+] Kono admin panel port open pawa jayni.{RESET}")
        return panel_info

    print(f"{YELLOW}[!] Admin panel port open: {panel_info['open_admin_ports']}{RESET}")

    # HTTP hole scheme http, 443 hole https
    for port in panel_info["open_admin_ports"]:
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{gateway_ip}:{port}/"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                code = resp.getcode()
                if code == 401:
                    panel_info["warning"].append(
                        f"Port {port}: Login required (401) - basic auth protected"
                    )
                else:
                    panel_info["warning"].append(
                        f"Port {port}: Page accessible (code {code}) - login page thakte pare"
                    )
        except urllib.error.HTTPError as e:
            if e.code == 401:
                panel_info["warning"].append(
                    f"Port {port}: Login required (401) - basic auth protected"
                )
        except Exception:
            pass

    # Default credentials check (sudhu HTTP Basic Auth support korle kaj korbe)
    print(f"{CYAN}[*] Common default credentials check kortesi (nijer router)...{RESET}")
    for port in panel_info["open_admin_ports"]:
        scheme = "https" if port == 443 else "http"
        for user, pw in DEFAULT_CREDS:
            url = f"{scheme}://{gateway_ip}:{port}/"
            try:
                pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                pwd_mgr.add_password(None, url, user, pw)
                handler = urllib.request.HTTPBasicAuthHandler(pwd_mgr)
                opener = urllib.request.build_opener(handler)
                resp = opener.open(url, timeout=2)
                if resp.getcode() == 200:
                    panel_info["weak_default_creds"] = True
                    panel_info["warning"].append(
                        f"Port {port}: DEFAULT CREDENTIALS WORKED ({user}/{pw}) - EKHONI PASSWORD BODLAO!"
                    )
                    break
            except urllib.error.HTTPError:
                continue
            except Exception:
                continue
        if panel_info["weak_default_creds"]:
            break

    if panel_info["weak_default_creds"]:
        print(f"{RED}{BOLD}[!!!] WARNING: Default credentials diye router login hoye gelo! Password change koro EKHONI.{RESET}")
    else:
        print(f"{GREEN}[+] Default credentials diye login hoyni (bhalo).{RESET}")

    return panel_info


def calculate_risk_score():
    total_risky = 0
    high_risk_ports = {21, 23, 139, 445, 3389}
    for host in results:
        for p in host["open_ports"]:
            if p in high_risk_ports:
                total_risky += 2
            else:
                total_risky += 1
    if router_report.get("weak_default_creds"):
        total_risky += 10
    elif router_report.get("open_admin_ports"):
        total_risky += 1
    return total_risky


def print_report():
    print(f"\n{CYAN}{BOLD}" + "=" * 50 + RESET)
    print(f"{CYAN}{BOLD}       WiFi NETWORK SECURITY AUDIT REPORT{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 50 + RESET)
    print(f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total devices found: {len(results)}")

    risky_hosts = [h for h in results if h["open_ports"]]
    count_color = RED if risky_hosts else GREEN
    print(f"{count_color}Devices with open risky ports: {len(risky_hosts)}{RESET}")

    high_risk_ports = {21, 23, 139, 445, 3389}
    for host in risky_hosts:
        print(f"\n  {BOLD}IP: {host['ip']}{RESET}")
        for rp in host["risky_ports"]:
            color = RED if rp["port"] in high_risk_ports else YELLOW
            print(f"    {color}- Port {rp['port']}: {rp['desc']}{RESET}")

    if router_report:
        print(f"\n  {BOLD}Router ({router_report.get('gateway_ip')}):{RESET}")
        if router_report.get("open_admin_ports"):
            print(f"    {YELLOW}- Admin panel open on ports: {router_report['open_admin_ports']}{RESET}")
            for w in router_report.get("warning", []):
                w_color = RED if "DEFAULT CREDENTIALS" in w else YELLOW
                print(f"    {w_color}- {w}{RESET}")
        else:
            print(f"    {GREEN}- Admin panel port open nei{RESET}")

    score = calculate_risk_score()
    print(f"\nOverall Risk Score: {BOLD}{score}{RESET}")
    if score == 0:
        print(f"{GREEN}{BOLD}Status: GOOD - Kono risky port open nei{RESET}")
    elif score <= 5:
        print(f"{YELLOW}{BOLD}Status: MODERATE - Kichu port check kora dorkar{RESET}")
    else:
        print(f"{RED}{BOLD}Status: HIGH RISK - Onek risky issue ache, ekhoni fix koro{RESET}")
    print(f"{CYAN}{BOLD}" + "=" * 50 + RESET)


def save_report():
    filename = f"wifi_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({
            "scan_time": datetime.now().isoformat(),
            "total_devices": len(results),
            "risk_score": calculate_risk_score(),
            "router": router_report,
            "results": results
        }, f, indent=2)
    print(f"[*] Report save hoise: {filename}")


def main():
    print_banner("MEHIDI_BRO")
    print("=" * 50)
    print("   WiFi Network Security Audit Tool")
    print("   (Sudhu nijer network-e use koro)")
    print("=" * 50)

    subnet, local_ip = get_local_subnet()
    if not subnet:
        print("[!] Network detect korte parlam na. WiFi connected ache?")
        return

    print(f"[*] Tomar IP: {local_ip}")
    print(f"[*] Subnet: {subnet}.0/24")

    scan_network(subnet)

    gateway_ip = get_default_gateway(subnet)
    if gateway_ip:
        global router_report
        router_report = check_admin_panel(gateway_ip)
    else:
        print(f"{YELLOW}[!] Router gateway IP ber kora gelo na, admin panel check skip.{RESET}")

    print_report()

    save = input("\nReport JSON file e save korbo? (y/n): ")
    if save.lower() == "y":
        save_report()


if __name__ == "__main__":
    main()
