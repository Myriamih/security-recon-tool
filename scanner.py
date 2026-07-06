import argparse
import concurrent.futures
import socket
import threading
import json
import PySimpleGUI as sg
import csv
from scapy.all import IP, TCP, sr1, conf

# Suppress Scapy verbose output
conf.verb = 0

OS_DB = {
    (64, 64240): "Linux (Kernel 2.4/2.6)",
    (64, 5720):  "Linux (Kernel 3.x/4.x)",
    (64, 65535): "macOS (Modern)",
    (128, 64240): "Windows 10/11",
    (128, 8192):  "Windows Server",
    (255, 4128):  "Cisco IOS"
}

def fingerprint_os(response):
    if not response or not response.haslayer(TCP): return "Unknown"
    ttl = response.ttl
    win = response[TCP].window
    guess = OS_DB.get((ttl, win))
    if not guess:
        if ttl <= 64: return "Linux/Unix-based"
        elif ttl <= 128: return "Windows-based"
        else: return "Unknown/Custom Appliance"
    return guess

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        s.close()
        return banner
    except:
        return "No banner received"

def check_vulnerabilities(banner):
    """Checks the banner against the local JSON database."""
    try:
        with open('vuln_db.json', 'r') as f:
            db = json.load(f)
            
        found_vulns = []
        for service, vuln_list in db.items():
            if service in banner:
                for entry in vuln_list:
                    if entry['version'] in banner:
                        found_vulns.append(entry['cve'])
        
        if found_vulns:
            return "[!] VULNERABILITIES: " + " | ".join(found_vulns)
        return "[+] No known vulnerabilities found."
    except FileNotFoundError:
        return "[?] vuln_db.json not found."
    except Exception as e:
        return f"[?] Database error: {e}"

def syn_scan(target_ip, port):
    response = sr1(IP(dst=target_ip)/TCP(dport=port, flags='S'), timeout=1)
    if response is None: return port, "Filtered", None
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12:
            sr1(IP(dst=target_ip)/TCP(dport=port, flags='R'), timeout=1)
            return port, "Open", response
        elif response[TCP].flags == 0x14: return port, "Closed", response
    return port, "Unknown", None

def export_to_csv(data_text):
    filename = sg.popup_get_file('Save as', save_as=True, file_types=(("CSV Files", "*.csv"),))
    if filename:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Audit Log"])
            for line in data_text.split('\n'):
                if line.strip():
                    writer.writerow([line])
        sg.popup(f"Results exported successfully!")

def run_scan_thread(target, port_range, window):
    try:
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
        total_ports = len(ports)
    except ValueError:
        window.write_event_value('-UPDATE-', "Error: Invalid port range format.")
        return
    
    window['-PROGRESS-'].update(0, max=total_ports)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_port = {executor.submit(syn_scan, target, p): p for p in ports}
        
        scanned_count = 0
        for future in concurrent.futures.as_completed(future_to_port):
            scanned_count += 1
            window['-PROGRESS-'].update(scanned_count)
            
            port, status, response = None, "Error", None
            try:
                port, status, response = future.result()
            except Exception as e:
                continue

            output = f"Port {port}: {status}"
            if status == "Open":
                banner = grab_banner(target, port)
                os_guess = fingerprint_os(response)
                vuln_report = check_vulnerabilities(banner)
                output += f" | Service: {banner} | OS: {os_guess} | {vuln_report}"
            
            window.write_event_value('-UPDATE-', output)

layout = [
    [sg.Text("Target IP:"), sg.Input(key='-TARGET-', size=(20,1), default_text="127.0.0.1")],
    [sg.Text("Port Range:"), sg.Input(key='-PORTS-', size=(10,1), default_text="20-100")],
    [sg.Button("Scan"), sg.Button("Export Results"), sg.Button("Exit")],
    [sg.ProgressBar(100, orientation='h', size=(50, 20), key='-PROGRESS-')],
    [sg.Multiline(size=(80, 20), key='-OUTPUT-', autoscroll=True, reroute_stdout=False)]
]

def main():
    window = sg.Window("Security Recon Tool", layout)
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, 'Exit'): break
        if event == 'Scan':
            window['-OUTPUT-'].update('')
            threading.Thread(target=run_scan_thread, args=(values['-TARGET-'], values['-PORTS-'], window), daemon=True).start()
        if event == 'Export Results':
            results = window['-OUTPUT-'].get()
            if results.strip():
                export_to_csv(results)
            else:
                sg.popup("No scan results available to export!")
        if event == '-UPDATE-':
            window['-OUTPUT-'].print(values['-UPDATE-'])
    window.close()

if __name__ == "__main__":
    main()