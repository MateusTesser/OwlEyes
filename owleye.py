import sys
import requests
import re
import socket
from aslookup import get_as_data
from random import randint
from pprint import pprint

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
def helpMenu():
	if len(sys.argv) < 2 or '-h' in sys.argv[:] or '--help' in sys.argv[:]:
		help = """OwlEyes is a information Gathering tool, can you use this options!
FIRST OPTIONS 	URL
--shodan, -s 	SHODAN_KEY
--censys, -c 	API_ID,SECRET_KEY
--gh, -g 	Google Hacking
--ssl 		Enable SSL
--help, -h 	Show this menu
		"""
		print(help)
		sys.exit(0)
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

def GoogleDork(url):
	from googlesearch import search
	from googlesearch import get_random_user_agent
	from time import sleep
	url = url.replace("http://","").replace("https://","")
	query = "site:"+url
	print("\n------------------------------------------------")
	print("             G O O G L E  D O R K S")
	print("------------------------------------------------\n")
	ua = get_random_user_agent()
	print("[*] Filtering by URL...\n")
	for urls in search(query, stop=10):
		print("[DORK]",urls)
	sleep(randint(6,15))
	query = 'site:pastebin.com "'+url+'"'
	print("\n[*] Searching leaks...")
	for urls in search(query, stop=10):
		print("[LEAKS]",urls)
	query = 'site:trello.com "'+url+'"'
	for urls in search(query, stop=10):
		print("[LEAKS]",urls)
	print("\n[*] Searching interesting files...\n")
	query = 'site:'+url+' filetype:sql'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:pdf'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:txt'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:ovpn'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:docx'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:doc'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:xls'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:xlsx'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:asp'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:aspx'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	query = 'site:'+url+' filetype:js'
	for urls in search(query, stop=5):
		print("[FILE]",urls)
	sleep(randint(6,15))
	print("\n[*] Searching Login pages...\n")
	query = 'site:'+url+' intitle:Login'
	for urls in search(query, stop=5):
		print("[PAGE]",urls)
	query = 'site:'+url+' intext:Login'
	for urls in search(query, stop=5):
		print("[PAGE]",urls)

def shodanSearch(url, token):
	import shodan
	try:
		from bs4 import BeautifulSoup
		from mitrecve import crawler
		api = shodan.Shodan(token)
		url = url.replace("http://","").replace("https://","")
		ip = socket.gethostbyname(url)
		#ip = "34.95.206.221"
		query = "hostname:leonardoonline.com.br"
		r = requests.get("https://www.shodan.io/search?query="+query+"&key="+token)
		ips=[]
		domains=[]
		soup = BeautifulSoup(r.text,features="lxml")
		x = soup.body.findAll('li', attrs={'class':'hostnames text-secondary'})
		for i in x:
			y=i.replace('<li class="hostnames text-secondary">','').replace('</li>','')
			try:
				if re.findall( r'[0-9]+(?:\.[0-9]+){3}', y):
					ips.append(y)
			except:
				domains.append(y)
		ips.append(ip)
		domains.append(url)
		print("\n------------------------------------------------")
		print("                    S H O D A N")
		print("------------------------------------------------\n")
		for i in ips:
			for j in domains:
				print('[IP]',i,j)
			host = api.host(i)
			print('[ORG]',host['org'])
			print('[OS]',end=' ')
			if host['os'] == None:
				print("Not identified!")
			else:
				print(host['os'])
			print("------------------------------------------------")
			for item in host['data']:
				print("[PORT]",item['port'])
				print('[BANNER]\n'+item['data'])
				print('[ASN]',item['asn'])
				print('[LOCATION]',item['location']['country_name'],end=" ")
				print(item['location']['country_code'], end=" ")
				print(item['location']['city'], end=" ")
				print(item['location']['region_code'])
				for e in item['opts']:
					print('[VULNS]',e)
				try:
					for i in host['vulns']:
						CVE = i.replace('!','')
						print("[CVE]",CVE,end=" ")
						print(crawler.get_cve_detail(CVE)[0][2])
				except KeyError:
					pass
				print("------------------------------------------------\n")
	except shodan.exception.APIError as e:
		print(e)
	# except:
	# 	print(f"Use: {sys.argv[0]} --shodan token")

def censysSearch(url, token):
	from censys.search import CensysHosts
	from censys.search import CensysCertificates
	try:
		api_id, secret = token.split(",")
	except:
		print(f"Use: {sys.argv[0]} --censys api_id,secret_key")
	ip = socket.gethostbyname(url)
	print("\n------------------------------------------------")
	print("                    C E N S Y S")
	print("------------------------------------------------\n")
	h = CensysHosts(str(api_id), str(secret))
	info = []
	for page in h.search(url):
		info += page
	for i in page:
		print("[IP]",i['ip'])
		b=i["services"]
		for j in b:
			print('[PORT]',j["port"],j["service_name"])
		print("[CONTINENT]",i['location']['continent'])
		print("[COUNTRY]",i['location']['country'],i['location']['country_code'])
		print("[TIMEZONE]",i['location']['timezone'])
		print("[REGISTERED COUNTRY]",i['location']['registered_country'],i['location']['registered_country_code'])
		print("\n------------------------------------------------")
	h = CensysCertificates(api_id, secret)
	certificate_query = 'parsed.names: '+url
	subdomains=[]
	certificates_search_results = h.search(certificate_query, fields=['parsed.names'])
	for search_result in certificates_search_results:
		subdomains.extend(search_result['parsed.names'])
	sub=[]
	for i in subdomains:
		if i in sub:
			pass
		else:
			sub.append(i)
	subdomains.clear()
	for i in sub:
		try:
			ip = socket.gethostbyname(str(i))
		except:
			ip="Not resolved"
		print("[SUBDOMAIN]",i,"-",ip)
try:
	print(banner)
	helpMenu()
	url = sys.argv[1]
	ssl = "http://"
	if '--ssl' in sys.argv[:]:
		ssl="https://"
	r = requests.get(ssl+url, allow_redirects=True, stream=True)
	r2 = requests.head(ssl+url, allow_redirects=True, stream=True)
	d = re.search('<\W*title\W*(.*)</title', r.text, re.IGNORECASE)
	ip = socket.gethostbyname(str(url))
	title = d.group(1)
	print("------------------------------------------------")
	print("             I N F O R M A T I O N S")
	print("------------------------------------------------\n")
	print(f"[INFO] Site title: {title}")
	print(f"[INFO] IP Address: {ip}")
	print(f"[INFO] Web Server: {r2.headers['server']}")
	ASN(ip)
	r = requests.get(ssl+url+"/robots.txt")
	print(f"[INFO] Robots?: ",end="")
	if r.status_code == 200:
		print("Founded!")
	else:
		print("Not founded!")
	r = requests.get(ssl+url+"/sitemap.xml")
	print(f"[INFO] Sitemap?: ",end="")
	if r.status_code == 200:
		print("Founded!")
	else:
		print("Not founded!")
	# print("[INFO] CMS: ",end="")
	# CMS(url)
	# print("[INFO] CloudFlare: ",end="")
	# if 'cloudflare' in r2.headers['server'].lower():
	# 	print("Yes")
	# else:
	# 	print("No")
	print("\n------------------------------------------------")
	print("                N E T W O R K")
	print("------------------------------------------------\n")
	rIP(ip)
	rDNS(ip)
	SubNetCalc(ip)
	DNSLookup(url)

	if '--shodan' in sys.argv[:]:
		token = sys.argv[sys.argv[:].index("--shodan")+1]
		shodanSearch(url, token)
	if '-s' in sys.argv[:]:
		token = sys.argv[sys.argv[:].index("-s")+1]
		shodanSearch(url, token)
	if '--censys' in sys.argv[:]:
		token = sys.argv[sys.argv[:].index("--censys")+1]
		censysSearch(url,token)
	if '-c' in sys.argv[:]:
		token = sys.argv[sys.argv[:].index("-c")+1]
		censysSearch(url,token)
	try:
		if sys.argv[2:].index("--gh") or sys.argv[1:].index("-g"):
			GoogleDork(url)
	except:
		pass

except IndexError:
	print(f"Use: {sys.argv[0]} http://yoururl.com")
except KeyboardInterrupt:
	print(f"\n\033[1m[\033[0;31m-\033[0m\033[1m]\033[0m Exiting...")