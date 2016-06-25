import requests
import ConfigParser

def getApiKey():
    config = ConfigParser.RawConfigParser()
    config.read("config.cfg")
    return config.get("google","key")

def getListNames(apiKey):
    r = requests.get("https://safebrowsing.googleapis.com/v4/threatLists", {'key': apiKey})
    if r.status_code < 400:
        respObject = r.json()
        return [x["threatType"] for x in respObject["threatLists"]]
    
    return []

print getListNames(getApiKey())

listRequest = { "client": { "clientId": "yourcompanyname", "clientVersion":  "1.5.2"}, "listUpdateRequests": [{"threatType": "MALWARE", "platformType": "ALL_PLATFORMS", "threatEntryType": "URL", "constraints": { "maxUpdateEntries": 2048, "region": "US", "supportedCompressions": ["RAW"]}}]}

r = requests.post("https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=" + getApiKey(), json=listRequest)
if r.status_code < 400:
    print r.json()
else:
    print r.text