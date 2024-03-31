# Target port and Security Header Checker Tool Buit by Minhaz

import optparse
import requests
import socket
import sys
from datetime import datetime
import threading

def display_banner():
    banner = """

   ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗          
   ██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗         
   ███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║         
   ██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║         
   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝██╗██╗██╗
   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝╚═╝╚═╝


       -by namikaze88
"""

    print(banner)

display_banner()

#resolve ip from the provided hostname
def resolve_target(hostname):
  try:
    target_ip = socket.gethostbyname(hostname)
    return target_ip
  except socket.gaierror:
    print("\n [X] Hostname Could Not Be Resolved !!!!")
    sys.exit()


# Set Deafult port and service list for scanning
def scan_default_ports(target_ip, output_file):
  default_ports = [(20, "FTP Data"), (21, "FTP Control"), (22, "SSH"),
                   (23, "Telnet"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"),
                   (110, "POP3"), (111, "RPCBIND"), (135, "Windows RPC"),
                   (139, "NetBIOS"),
                   (143, "IMAP"), (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"),
                   (995, "POP3S"), (1723, "PPTP"), (3306, "MySQL"),
                   (3389, "Remote Desktop"), (5060, "SIP"), (5061, "SIPS"),
                   (5432, "PostgreSQL"), (5900, "VNC"), (5984, "CouchDB"),
                   (6379, "Redis"), (8080, "HTTP Alt"), (8443, "HTTPS Alt")]

  try: 
    with open(output_file, 'a') as f:
      f.write("-" * 50 + '\n')
      f.write(" [+] Scanning Target IP: " + target_ip + '\n')
      f.write(" [+] Scanning started at:" + str(datetime.now()) + '\n')
      f.write("-" * 50 + '\n')

    print("-" * 50)
    print(" [+] Scanning Target IP: " + target_ip)
    print(" [+] Scanning started at:" + str(datetime.now()))
    print("-" * 50)

    # Treads for concurrecy
    threads = []
    for port, service_name in default_ports:
      thread = threading.Thread(target=scan_port,
                                args=(target_ip, port, service_name,
                                      output_file))
      threads.append(thread)
      thread.start()

    for thread in threads:
      thread.join()

    with open(output_file, 'a') as f:
      f.write("\n [+] Scanning finished at:" + str(datetime.now()) + '\n')
      f.write("-" * 50 + '\n')

    print(" [+] Scanning finished at:" + str(datetime.now()))
    print("-" * 50)

  except KeyboardInterrupt:
    print("\n Terminating the program !!!!")
    sys.exit()


# Port Scan Section
def scan_port(target_ip, port, service_name, output_file):
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(1)
      s.connect((target_ip, port))
      result = f" Port {port} ({service_name}) is open\n"
      with open(output_file, 'a') as f:
        f.write(result)
      print(result)

  except (socket.timeout, ConnectionRefusedError):
    pass


# Checking security header section
def check_security_headers(target, output_file):
  if not target.startswith("http://") and not target.startswith("https://"):
    target = "https://" + target
  try:
    response = requests.get(target)
    security_headers = {
        "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options",
        "X-XSS-Protection", "Strict-Transport-Security", "Referrer-Policy"
    }
    missing_headers = []
    correctly_set_headers = []

    for header in security_headers:
      if header not in response.headers:
        missing_headers.append(header)
      else:
        correctly_set_headers.append(header)

    with open(output_file, 'a') as f:
      if correctly_set_headers:
        f.write(
            " [✓] Security header scanning started, Correctly set headers showing below:\n"
        )
        for header in correctly_set_headers:
          f.write(f" [✓] {header} is correctly set.\n")
        print(
            " [✓] Security header scanning started, Correctly set headers showing below:\n"
        )
        for header in correctly_set_headers:
          print(f" [✓] {header} is correctly set.")

    # Print missing header
      if missing_headers:
        f.write("\n")
        f.write("-" * 50 + '\n')
        f.write("\n [x] Result of Missing Headers showing below:\n")
        f.write(f"\n [x] Misiing Header: {missing_headers}\n")

        print("-" * 50)
        print("\n [x] Result of Missing Headers showing below:")
        print(f"\n [x] Misiing Header: {missing_headers}\n")

      if not (correctly_set_headers or missing_headers):
        f.write("All security headers are correctly set.\n")
        print("All security headers are correctly set.")

      # Print scanning finished time
      f.write("\n [+] Scanning finished at:" + str(datetime.now()) + '\n')
      print("\n [+] Scanning finished at:" + str(datetime.now()) + '\n')

  except requests.RequestException as e:
    with open(output_file, 'a') as f:
      f.write(f"Error occurred: {e}\n")
    print(f"Error occurred: {e}")


# Main function for getting user input
def main():
  parser = optparse.OptionParser()
  parser.add_option("-t",
                    "--target",
                    dest="target",
                    help="Target hostname for port scanning")
  parser.add_option("-o",
                    "--output",
                    dest="output",
                    default="scan_results.txt",
                    help="Output file name")
  (options, arguments) = parser.parse_args()
  target = options.target
  output_file = options.output

  if target:
    target_ip = resolve_target(target)
    scan_default_ports(target_ip, output_file)
    check_security_headers(target, output_file)

  else:
    print(" [X] Invalid Argument. You must enter the hostname.")


if __name__ == "__main__":
  main()
