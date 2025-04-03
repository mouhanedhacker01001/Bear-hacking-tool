import time
import socket
import requests
import os
from scapy.all import ARP, Ether, srp
from colorama import Fore, Style, init
from ftplib import FTP
import paramiko
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama for colored console output.
init(autoreset=True)

# Define a list of common ports.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1080,
    1433, 3306, 3389, 8080, 8443
]

# FTP brute force function.
def ftp_bruteforce(target_ip, username, wordlist):
    try:
        with open(wordlist, 'r') as file:
            for password in file:
                password = password.strip()
                try:
                    ftp = FTP(target_ip, timeout=5)
                    ftp.login(user=username, passwd=password)
                    print(f"{Fore.GREEN}[+] FTP login successful! User: {username} | Password: {password}")
                    ftp.quit()
                    return
                except Exception:
                    continue
        print(f"{Fore.RED}[-] FTP brute force failed. No valid password found.")
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: Wordlist file not found.")

# SSH brute force function.
def ssh_bruteforce(target_ip, username, wordlist):
    try:
        with open(wordlist, 'r') as file:
            for password in file:
                password = password.strip()
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(target_ip, username=username, password=password, timeout=5)
                    print(f"{Fore.GREEN}[+] SSH login successful! User: {username} | Password: {password}")
                    ssh.close()
                    return
                except Exception:
                    continue
        print(f"{Fore.RED}[-] SSH brute force failed. No valid password found.")
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: Wordlist file not found.")

# Port scanning function using a thread pool for speed.
def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                return port
    except Exception:
        return None

def port_scanner(target):
    open_ports = []
    print(f"{Fore.CYAN}[~] Scanning target {target} on common ports...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, target, port): port for port in COMMON_PORTS}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result() is not None:
                    print(f"{Fore.GREEN}[+] Port {port} is open on {target}")
                    open_ports.append(port)
            except Exception:
                continue
    if not open_ports:
        print(f"{Fore.RED}[-] No open ports found on {target}.")

# Web scanner function.
def web_scanner(target_url):
    try:
        response = requests.get(target_url, timeout=5)
        print(f"{Fore.CYAN}[~] Scanning {target_url}...")
        print(f"{Fore.YELLOW}[i] Status Code: {response.status_code}")
        print(f"{Fore.YELLOW}[i] Headers: {response.headers}")
        # Attempt to retrieve robots.txt
        robots_url = target_url.rstrip("/") + "/robots.txt"
        r = requests.get(robots_url, timeout=5)
        if r.status_code == 200:
            print(f"{Fore.GREEN}[+] robots.txt found at {robots_url}:\n{r.text}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Error: Unable to reach the target website. {e}")

# Directory scanner function.
def directory_scanner(target_url, wordlist):
    try:
        with open(wordlist, "r") as file:
            directories = file.read().splitlines()
        print(f"{Fore.CYAN}[~] Scanning directories on {target_url}...")
        for dir in directories:
            full_url = f"{target_url.rstrip('/')}/{dir.lstrip('/')}"
            try:
                response = requests.get(full_url, timeout=5)
                if response.status_code == 200:
                    print(f"{Fore.GREEN}[+] Found: {full_url}")
            except requests.exceptions.RequestException:
                continue
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: Wordlist file not found.")

# Discover devices in the local network via ARP.
def discover_devices_in_lan(network_range):
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    print(f"{Fore.CYAN}[~] Devices discovered on the network:")
    for element in answered_list:
        print(f"{Fore.GREEN}[+] IP: {element[1].psrc} | MAC: {element[1].hwsrc}")

# Main menu function.
def main():
    print(f"""
{Fore.CYAN}_______
  _____|       |_____
 |___________________|
    |           |
    |           | 
    |  |     |  |
    _____________ 
    |    |___|   |
    |____________|   
{Fore.GREEN}WELCOME TO Bear Hacking Tool

{Fore.YELLOW}1. Port scanner
2. Web scanner
3. SSH, HTTP, HTTPS, FTP, SMTP scanner
4. Web directory scanner
5. Brute forcing (FTP/SSH)
6. Exploitation
7. Hashes unlocker (binary, base64, base32, md5, md4 ...)
8. Discover devices in LAN
""")
    choice = input(f"{Fore.MAGENTA}Choose an option for penetration testing: {Fore.WHITE}")
    
    if choice == "1":
        target_ip = input(f"{Fore.YELLOW}[+] Enter target IP (v4): {Fore.WHITE}")
        port_scanner(target_ip)
    elif choice == "2":
        target_url = input(f"{Fore.YELLOW}Enter the target URL: {Fore.WHITE}")
        web_scanner(target_url)
    elif choice == "3":
        target_ip = input(f"{Fore.YELLOW}Enter the target IP: {Fore.WHITE}")
        service_ports = COMMON_PORTS
        for port in service_ports:
            scan_port(target_ip, port)
    elif choice == "4":
        target_url = input(f"{Fore.YELLOW}Enter the target URL: {Fore.WHITE}")
        wordlist_path = input(f"{Fore.YELLOW}Enter the path to the wordlist: {Fore.WHITE}")
        directory_scanner(target_url, wordlist_path)
    elif choice == "5":
        print(f"{Fore.YELLOW}Brute Force Options:\n1. FTP\n2. SSH")
        attack_choice = input(f"{Fore.MAGENTA}Choose attack method: {Fore.WHITE}")
        target_ip = input(f"{Fore.YELLOW}[+] Enter target IP: {Fore.WHITE}")
        username = input(f"{Fore.YELLOW}[+] Enter target username: {Fore.WHITE}")
        wordlist_path = input(f"{Fore.YELLOW}Enter the path to the wordlist: {Fore.WHITE}")
        if attack_choice == "1":
            ftp_bruteforce(target_ip, username, wordlist_path)
        elif attack_choice == "2":
            ssh_bruteforce(target_ip, username, wordlist_path)
        else:
            print(f"{Fore.RED}[-] Invalid brute force option.")
    elif choice == "8":
        network_range = input(f"{Fore.YELLOW}Enter network range (e.g., 192.168.1.1/24): {Fore.WHITE}")
        discover_devices_in_lan(network_range)
    else:
        print(f"{Fore.RED}[-] Error: Invalid choice.")
    
    time.sleep(5)

if __name__ == "__main__":
    main()

