import sys
import requests
import re
from aslookup import get_as_data

banner = """
 ▒█████   █     █░ ██▓       ▓█████▓██   ██▓▓█████   ██████  ▐██▌ 
▒██▒  ██▒▓█░ █ ░█░▓██▒       ▓█   ▀ ▒██  ██▒▓█   ▀ ▒██    ▒  ▐██▌ 
▒██░  ██▒▒█░ █ ░█ ▒██░       ▒███    ▒██ ██░▒███   ░ ▓██▄    ▐██▌ 
▒██   ██░░█░ █ ░█ ▒██░       ▒▓█  ▄  ░ ▐██▓░▒▓█  ▄   ▒   ██▒ ▓██▒ 
░ ████▓▒░░░██▒██▓ ░██████▒   ░▒████▒ ░ ██▒▓░░▒████▒▒██████▒▒ ▒▄▄  
░ ▒░▒░▒░ ░ ▓░▒ ▒  ░ ▒░▓  ░   ░░ ▒░ ░  ██▒▒▒ ░░ ▒░ ░▒ ▒▓▒ ▒ ░ ░▀▀▒ 
  ░ ▒ ▒░   ▒ ░ ░  ░ ░ ▒  ░    ░ ░  ░▓██ ░▒░  ░ ░  ░░ ░▒  ░ ░ ░  ░ 
░ ░ ░ ▒    ░   ░    ░ ░         ░   ▒ ▒ ░░     ░   ░  ░  ░      ░ 
    ░ ░      ░        ░  ░      ░  ░░ ░        ░  ░      ░   ░    
                                    ░ ░                     
	<----------Information Gathering tool---------->
"""
def rIP(ip):
	req = requests.get("https://api.hackertarget.com/reverseiplookup/?q="+ip, stream=True)
	for lines in req.iter_lines():
		print("[rIP]", lines.decode("utf-8"))
def rDNS(ip):
	req = requests.get("https://api.hackertarget.com/reversedns/?q="+ip, stream=True)
	for lines in req.iter_lines():
		print("[rDNS]", lines.decode("utf-8"))
def SubNetCalc(ip):
	req = requests.get("http://api.hackertarget.com/subnetcalc/?q="+ip, stream=True)
	for lines in req.iter_lines():
		print("[SubNet Calc]", lines.decode("utf-8"))
def DNSLookup(url):
	url = url.replace("https://","").replace("http://","")
	req = requests.get("http://api.hackertarget.com/dnslookup/?q="+url, stream=True)
	for lines in req.iter_lines():
		print("[DNS Lookup]", lines.decode("utf-8"))

def CMS(url):
	req = requests.get(url)
	if re.search("/wp-content/",str(req.content)):
		print("WordPress!")
	elif re.search("Joomla",str(req.content)):
		print("Joomla!")
	r = requests.get(url+"/adminstrator/")
	if r.status_code == 200 or r.status_code == 401 or r.status_code == 403:
		print("Joomla!")
	r = requests.get(url+"/misc/drupal.js")
	resp = r.status_code == 200
	if r.status_code == 200:
		print("Drupal!")
	r = requests.get(url+"/skin/frontend/")
	if r.status_code == 200:
		print("Magento!")
	elif re.search("content=WordPress",str(req.content)):
		print("WordPress!")
	else:
		print("Not founded!")
	r = requests.get(url+"/config.inc.php")
	if r.status_code == 200:
		print("phpMyAdmin")

def ASN(ip):
	a, _ , b , _, _, c, d, _,f,_= get_as_data(ip)
	print(f"[INFO] ASN: {a} {b} {c} {d}")

try:
	print(banner)
	url = sys.argv[1]
	r = requests.get(url, allow_redirects=True, stream=True)
	r2 = requests.head(url, allow_redirects=True, stream=True)
	d = re.search('<\W*title\W*(.*)</title', r.text, re.IGNORECASE)
	ip = socket.gethostbyname(str(url.replace("http://","").replace("https://","")))
	title = d.group(1)

	print("------------------------------------------------")
	print("             I N F O R M A T I O N S")
	print("------------------------------------------------\n")
	print(f"[INFO] Site title: {title}")
	print(f"[INFO] IP Address: {ip}")
	print(f"[INFO] Web Server: {r2.headers['server']}")
	ASN(ip)
	r = requests.get(url+"/robots.txt")
	print(f"[INFO] Robots?: ",end="")
	if r.status_code == 200:
		print("Founded!")
	else:
		print("Not founded!")
	print("[INFO] CMS: ",end="")
	CMS(url)
	print("[INFO] CloudFlare: ",end="")
	if 'cloudflare' in r2.headers['server'].lower():
		print("Yes")
	else:
		print("No")
	print("\n------------------------------------------------")
	print("                N E T W O R K!")
	print("------------------------------------------------\n")
	rIP(ip)
	rDNS(ip)
	SubNetCalc(ip)
	DNSLookup(url)
except IndexError:
	print(f"Use: {sys.argv[0]} http://yoururl.com")
except KeyboardInterrupt:
	print(f"\n\033[1m[\033[0;31m-\033[0m\033[1m]\033[0m Exiting...")