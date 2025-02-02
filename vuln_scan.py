from flask import Flask, render_template, request
import random
import string
import requests
import socket
import nmap
import base64
import urllib.parse
import hashlib
import subprocess
import httpx

app = Flask(__name__)

# Subdomain Finder (Basic Implementation)
def find_subdomains(domain):
    common_subdomains = ['www', 'mail', 'ftp', 'blog', 'test', 'email', 'pop', 'pop3', 'smtp', 'admin', 'cpanel', 'dev', 'portal']
    found = []
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)  # Try to resolve the subdomain
            found.append(subdomain)  # If it resolves, append to results
        except socket.gaierror:
            pass  # Ignore if the subdomain does not exist
    return found

# Password Generator
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# IP Information Lookup
def get_ip_info(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
    except:
        data = {"error": "Could not retrieve IP details"}
    return data

# Breach Check using Have I Been Pwned API
def check_email_breach(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": "your_api_key_here"}  # Replace with a valid API key
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {"error": "Email not found in breaches"}

# Nmap Vulnerability Scanner
def scan_vulnerabilities(target):
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments='-sV')
        results = {}
        for host in scanner.all_hosts():
            results[host] = []
            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service = scanner[host][proto][port]['name']
                    results[host].append(f"Port {port}: {service}")
        return results
    except Exception as e:
        return {"error": f"Nmap scan failed: {str(e)}"}

# Nikto Scan
def run_nikto(target):
    try:
        nikto_output = subprocess.check_output(['perl', '/home/user/Downloads/nikto/program/nikto.pl', '-h', target], stderr=subprocess.STDOUT)
        return nikto_output.decode()
    except subprocess.CalledProcessError as e:
        return f"Error running Nikto: {e.output.decode()}"

# HTTPX Probe
def run_httpx(target):
    try:
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target  # Add the default protocol
            
        client = httpx.Client()
        response = client.get(f"http://{target}")
        return f"HTTPX Status: {response.status_code}"
    except httpx.RequestError as e:
        return f"HTTPX probe failed: {str(e)}"

# Hash Generator
def generate_hash(text, hash_type):
    hash_functions = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512
    }
    if hash_type in hash_functions:
        return hash_functions[hash_type](text.encode()).hexdigest()
    return "Invalid hash type"

# Encoder Tool
def encode_text(text, encoding_type):
    if encoding_type == "base64":
        return base64.b64encode(text.encode()).decode()
    elif encoding_type == "url":
        return urllib.parse.quote(text)
    elif encoding_type == "hex":
        return text.encode().hex()    
    return "Invalid encoding type"

# Google Dorking Query Generator
def generate_google_dork(query, dork_type):
    dork_templates = {
        "site": f"site:{query}",
        "filetype": f"filetype:{query}",
        "intitle": f"intitle:{query}",
        "inurl": f"inurl:{query}",
        "intext": f"intext:{query}"
    }
    return dork_templates.get(dork_type, "Invalid Dork Type")

# Home Page
@app.route('/')
def home():
    return render_template('index.html')

# Subdomain Finder Route
@app.route('/subdomain-generator-link')
def subdomain_generator():
    return render_template('subdomain_generator.html')

@app.route('/generate-subdomains', methods=['POST'])
def generate_subdomains():
    domain = request.form.get('domain')  # Get the domain from the form
    if not domain:
        return render_template('subdomain_generator.html', error="Please provide a valid domain.")
    
    subdomains = find_subdomains(domain)  # Call find_subdomains to get the results
    return render_template('subdomain_generator.html', domain=domain, subdomains=subdomains)

# Password Generator Route
@app.route('/password-generator-link')
def password_generator():
    return render_template('password_generator.html')

@app.route('/generate-password', methods=['POST'])
def generate_password_route():
    length = int(request.form.get('length', 12))  # Default length is 12
    password = generate_password(length)
    return render_template('password_generator.html', password=password)

# IP Info Route
@app.route('/ip-info-link')
def ip_info():
    return render_template('ip_info.html')

@app.route('/get-ip-info', methods=['POST'])
def get_ip_info_route():
    ip_address = request.form.get('ip_address')
    data = get_ip_info(ip_address)
    return render_template('ip_info.html', data=data)

# Domain Generator Route
@app.route('/domain-generator-link')
def domain_generator():
    return render_template('domain_generator.html')

@app.route('/generate-domain', methods=['POST'])
def generate_domain():
    keyword = request.form.get('keyword')
    domains = [f"{keyword}{random.randint(100,999)}.com",
               f"{keyword}-secure.net",
               f"get{keyword}.org"]
    return render_template('domain_generator.html', domains=domains)

# Breach Check Route
@app.route('/breach-check-link')
def breach_check():
    return render_template('breach_check.html')

@app.route('/check-breach', methods=['POST'])
def breach_check_route():
    email = request.form.get('email')
    results = check_email_breach(email)
    return render_template('breach_check.html', results=results)

# Google Dorking Route
@app.route('/google-dorking-link')
def google_dorking():
    return render_template('google_dorking.html')

@app.route('/generate-google-dork', methods=['POST'])
def generate_google_dork_route():
    query = request.form.get('query')
    dork_type = request.form.get('dork_type')
    dork_result = generate_google_dork(query, dork_type)
    return render_template('google_dorking.html', dork_result=dork_result)

# Encoder Tool Route
@app.route('/encoder-link')
def encoder():
    return render_template('encoder.html')

@app.route('/encode-data', methods=['POST'])
def encode_data():
    text = request.form.get('text')
    encoding_type = request.form.get('encoding_type')

    if not text or not encoding_type:
        return render_template('encoder.html', error="Text and encoding type are required.")

    encoded_text = encode_text(text, encoding_type)
    return render_template('encoder.html', encoded_text=encoded_text)

# Vulnerability Scanner Route      
@app.route('/vulnerability-scanner-link', methods=['GET', 'POST'])
def vulnerability_scanner():
    if request.method == 'POST':
        target = request.form.get('website-url')
        if not target:
            return render_template('vulnerability_scanner.html', error="Please provide a valid target URL or IP.")
        
        # Nmap Scan
        nmap_results = scan_vulnerabilities(target)
        
        # Nikto Scan
        nikto_results = run_nikto(target)
        
        # HTTPX Probe
        httpx_results = run_httpx(target)
        
        # Debugging: print the results to help troubleshoot
        print(f"Nmap Results: {nmap_results}")
        print(f"Nikto Results: {nikto_results}")
        print(f"HTTPX Results: {httpx_results}")
        
        return render_template('scanner_result.html', 
                               url=target, 
                               nmap_results=nmap_results, 
                               nikto_results=nikto_results, 
                               httpx_results=httpx_results)
    return render_template('vulnerability_scanner.html')

# Hash Generator Route
@app.route('/hash-generator-link')
def hash_generator():
    return render_template('hash_generator.html')

@app.route('/generate-hash', methods=['POST'])
def generate_hash_route():
    text = request.form.get('text')
    hash_type = request.form.get('hash_type')
    hash_result = generate_hash(text, hash_type)
    return render_template('hash_generator.html', hash_result=hash_result)

if __name__ == '__main__':
    app.run(debug=True)
