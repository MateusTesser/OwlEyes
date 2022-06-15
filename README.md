# OwlEyes
Information Gathering tool using python3

```
Usage: python3 owleyes.py https://google.com
```
![Tool](https://raw.githubusercontent.com/MateusTesser/OwlEyes/main/image/print.png)

You can now use Shodan, Censys.io and Google Hacking

Shodan massive scan from URL, getting IPs and CVEs
```
$ python3 owleye.py URL --shodan SHODAN KEY
```
Censys search ports, services and subdomains
```
$ python3 owleye.py URL --shodan API_ID,SECRET_KEY
```
Google Hacking
```
$ python3 owleye.py URL --gh
```
Wayback Machine
```
$ python3 owleye.py URL --wayback
```
All parameters:
```
--shodan, -s 	SHODAN_KEY
--censys, -c 	API_ID,SECRET_KEY
--gh, -g        Google Hacking
-ssl		Enable SSL
--wayback, -w   WAYBACK MACHINE
```
![HelpMenu](https://raw.githubusercontent.com/MateusTesser/OwlEyes/main/image/Screenshot%20from%202022-06-09%2016-27-07.png)
## Dependecies:
You need to have python3 installed
```
$ pip3 install aslookup requests google cssselect shodan censys mitrecve bs4
```
