import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Dynamicweb Login Panel''',
        "description": '''''',
        "severity": "info",
        "references": [
            "https://www.dynamicweb.com"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "shodan-query":'''http.component:"Dynamicweb"'''
        },
        "tags": ["panel", "dynamicweb"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/Admin/Access/default.aspx"""
        method = "GET"
        data = """"""
        headers = {'Accept-Encoding': 'gzip, deflate'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""Dynamicweb""" in resp0.text) and (resp0.status_code == 200):
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