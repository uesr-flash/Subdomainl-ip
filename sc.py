import tkinter as tk
from tkinter import filedialog
import socket

def resolve_subdomain(subdomain: str) -> list:
    try:
        ip_addresses = socket.gethostbyname_ex(subdomain)
        return ip_addresses[2]
    except socket.gaierror:
        return []

def scan_subdomains(domain: str) -> dict:
    subdomains = {}
    with open("subdomains.txt") as file:
        for line in file:
            subdomain = line.strip() + '.' + domain
            ips = resolve_subdomain(subdomain)
            if ips:
                subdomains[subdomain] = ips
    return subdomains

def scan_domain():
    domain = entry.get()  #freebuf.com
    subdomains = scan_subdomains(domain)

    if subdomains:
        result_text.config(state="normal")
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, f"Subdomains found for {domain}:\n")
        for subdomain, ips in subdomains.items():
            result_text.insert(tk.END, f"{subdomain}\n")
            result_text.insert(tk.END, ''.join(ips))
            result_text.insert(tk.END, "\n\n\n")
        result_text.config(state="disabled")
    else:
        result_text.config(state="normal")
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, f"No subdomains found for {domain}")
        result_text.config(state="disabled")

def scan_file():
    file_path = filedialog.askopenfilename()
    domains = []
    with open(file_path) as file:
        domains = file.readlines()
    domains = [domain.strip() for domain in domains]

    for domain in domains:
        subdomains = scan_subdomains(domain)
"""
def add_subdomains_from_dict(dict_file: str):
    with open(dict_file) as file:
        subdomains = file.readlines()
    subdomains = [subdomain.strip() for subdomain in subdomains]

    with open("subdomains.txt", "a") as file:
        for subdomain in subdomains:
            file.write(subdomain + "\n")
"""
window = tk.Tk()
window.title("Subdomain Scanner")

label = tk.Label(window, text="Enter a domain:")
label.pack()
entry = tk.Entry(window)
entry.pack()

scan_button = tk.Button(window, text="Scan Domain", command=scan_domain)
scan_button.pack()

file_scan_button = tk.Button(window, text="Scan File", command=scan_file)
file_scan_button.pack()

result_text = tk.Text(window, state="disabled")
result_text.pack()

try:
    with open("subdomains.txt", "x") as file:
        file.write("subdomain1\nsubdomain2\nsubdomain3")
except FileExistsError:
    pass

window.mainloop()
