# This script retrieve VirusTotal URL scan reports
# 2016/2  by mona4911

import json
import urllib
import urllib2
url = "https://www.virustotal.com/vtapi/v2/url/report"
targeturl = raw_input()
parameters = {"resource": targeturl,
              "apikey": "your api key"}
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)
response = urllib2.urlopen(req)
jsonstr = response.read()
#print json

decjson = json.loads(jsonstr)

print decjson["scan_date"] + ",",
print decjson["url"] + ",",
print str(decjson["positives"]) + ",",
print str(decjson["total"]) + ",",


#decscans = json.loads(decjson["scans"])
count = 0

for attr in decjson["scans"].keys():
    if decjson["scans"][attr]["detected"]:
      if count != 0:
        print ";",
      print attr + ":",
      print decjson["scans"][attr]["result"],
      count += 1

