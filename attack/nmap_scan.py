import nmap

scanner = nmap.PortScanner()

target = input("Enter target IP: ")

print(f"\n[*] Scanning {target} — ports 1 to 65535...")
print("[*] This may take a few minutes...\n")

scanner.scan(target, "1-65535", arguments="-T4")

for host in scanner.all_hosts():
    print(f"Host  : {host}  ({scanner[host].state()})")
    print("-" * 40)
    
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        open_ports = [p for p in ports if scanner[host][proto][p]['state'] == 'open']
        
        print(f"\nOpen ports ({proto.upper()}):\n")
        for port in sorted(open_ports):
            service = scanner[host][proto][port].get('name', 'unknown')
            print(f"  Port {port:5d}  →  {service}")

print("\n[*] Scan complete.")