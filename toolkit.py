import hashlib
import socket
from ftplib import FTP
import threading

def scan_ports(target,start_port,end_port):
    print(f"[+] Scanning {target}...")
    def port_scan(target,port):
        try:
            s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                print(f"[OPEN] Port {port}")
        except Exception as e:
            print(f"[-] Error scanning port {port}: {e}")
            
    for port in range(start_port,end_port+1):
        thread = threading.Thread(target=port_scan,args=(port,))
        thread.start()
    


def ftp_bruteforce(host, user, wordlist):
    with open(wordlist, 'r') as f:
        for password in f:
            password = password.strip()
            try:
                ftp = FTP(host)
                ftp.login(user, password)
                print(f"[+] Success: {user}:{password}")
                ftp.quit()
                return
            except:
                print(f"[-] Failed: {password}")

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.connect((ip, port))
            s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = s.recv(1024).decode()
            print(f"[+] Banner for {ip}:{port}:\n{banner}")
    except Exception as e:
        print(f"[-] Could not grab banner: {e}")



def crack_hash(hash_to_crack, wordlist, algo='md5'):
    with open(wordlist, 'r') as f:
        for word in f:
            word = word.strip()
            hash_func = getattr(hashlib, algo)
            if hash_func(word.encode()).hexdigest() == hash_to_crack:
                print(f"[+] Cracked: {word}")
                return
    print("[-] No match found.")

def main():
    print("\n--- PenTest Toolkit ---")
    print("1. Port Scanner")
    print("2. FTP Brute Forcer")
    print("3. Banner Grabber")
    print("4. Hash Cracker")
    choice = input("Choose an option: ")

    if choice == "1":
        target = input("Target: ")
        start_port=int(input("start_port: "))
        end_port=int(input("end_port: "))
        target = socket.gethostbyname(target)
        scan_ports(target, start_port,end_port)
   

    elif choice == "2":
        host = input("FTP Host: ")
        user = input("Username: ")
        wordlist = input("Path to wordlist: ")
        ftp_bruteforce(host, user, wordlist)

    elif choice == "3":
        ip = input("Target IP: ")
        port = int(input("Port: "))
        grab_banner(ip, port)

    elif choice == "4":
        hash_to_crack = input("Hash: ")
        algo = input("Algorithm (md5/sha1): ").strip()
        wordlist = input("Wordlist file: ")
        crack_hash(hash_to_crack, wordlist, algo)

    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()