import socket, whois, requests, datetime, os
from bs4 import BeautifulSoup

def whois_lookup(domain):
    try:
        return whois.whois(domain).text
    except Exception as e:
        return f"WHOIS Error: {e}"

def subdomain_enum(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=10)
        subdomains = list({item['name_value'] for item in r.json()})
        return subdomains
    except Exception as e:
        return [f"Error fetching subdomains: {e}"]

def port_scan(domain, ports=[21,22,80,443,8080]):
    open_ports = []
    for port in ports:
        try:
            with socket.create_connection((domain, port), timeout=1) as sock:
                open_ports.append(port)
        except:
            continue
    return open_ports

def banner_grab(domain, ports=[80, 443]):
    banners = {}
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((domain, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % domain.encode())
            data = s.recv(1024).decode(errors="ignore")
            banners[port] = data
            s.close()
        except:
            banners[port] = "No banner"
    return banners

def tech_detect(domain):
    try:
        r = requests.get(f"http://{domain}", timeout=3)
        tech = []
        if 'server' in r.headers:
            tech.append(f"Server: {r.headers['server']}")
        if 'x-powered-by' in r.headers:
            tech.append(f"Powered by: {r.headers['x-powered-by']}")
        return tech or ["No tech headers found"]
    except Exception as e:
        return [f"Error: {e}"]

def generate_txt_report(results, filepath):
    with open(filepath, 'w') as f:
        for section, content in results.items():
            f.write(f"===== {section.upper()} =====\n")
            if isinstance(content, list):
                f.writelines(f"{line}\n" for line in map(str, content))
            elif isinstance(content, dict):
                for k,v in content.items():
                    f.write(f"{k}: {v}\n")
            else:
                f.write(f"{content}\n")
            f.write("\n")

def generate_html_report(results, filepath):
    html = "<html><head><title>Recon Report</title></head><body><h1>Reconnaissance Summary</h1>"
    for section, content in results.items():
        html += f"<h2>{section.upper()}</h2><pre>"
        if isinstance(content, list):
            html += "\n".join(str(item) for item in content)
        elif isinstance(content, dict):
            html += "\n".join(f"{k}: {v}" for k, v in content.items())
        else:
            html += str(content)
        html += "</pre>"
    html += "</body></html>"
    with open(filepath, "w") as f:
        f.write(html)

def main():
    print("=== Simple Python Recon Tool === ")
    print("  _Created by Madhan Motiyani_")
    print("         === V 1.0 ===")
    
     
    domain = input("Enter target domain: ").strip()
    if not domain:
        print("[-] No domain provided.")
        return

    save_dir = input("Enter folder path to save the reports (leave blank for current directory): ").strip()
    if not save_dir:
        save_dir = os.getcwd()
    elif not os.path.exists(save_dir):
        try:
            os.makedirs(save_dir)
            print(f"[+] Created directory: {save_dir}")
        except Exception as e:
            print(f"[-] Failed to create directory: {e}")
            return

    print(f"[+] Starting Recon on: {domain}")
    
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        print(f"[-] Could not resolve domain: {e}")
        return

    timestamp = datetime.datetime.now().isoformat()

    results = {
        "Target": domain,
        "Resolved IP": ip,
        "Timestamp": timestamp,
        "WHOIS": whois_lookup(domain),
        "Subdomains": subdomain_enum(domain),
        "Open Ports": port_scan(domain),
        "Banners": banner_grab(domain),
        "Technologies": tech_detect(domain)
    }

    txt_file = os.path.join(save_dir, f"{domain}_report.txt")
    html_file = os.path.join(save_dir, f"{domain}_report.html")

    generate_txt_report(results, txt_file)
    generate_html_report(results, html_file)

    print(f"[+] TXT report saved to: {txt_file}")
    print(f"[+] HTML report saved to: {html_file}")

if __name__ == "__main__":
    main()
