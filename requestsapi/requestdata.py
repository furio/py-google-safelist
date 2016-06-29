import requests
import responseobjects

class RequestData(object):
    def __init__(self,apikey,companyname):
        self.__apikey = apikey
        self.__reqobj = {"client": { "clientId": companyname, "clientVersion":  "1.5.2"}, "listUpdateRequests": [{"threatType": "", "platformType": "ANY_PLATFORM", "threatEntryType": "URL", "constraints": { "maxUpdateEntries": 4096, "region": "US", "supportedCompressions": ["RAW"]}}]}

    def getthreatlists(self):
        r = requests.get("https://safebrowsing.googleapis.com/v4/threatLists", {'key': self.__apikey})
        if r.status_code < 400:
            respObject = r.json()
            return [x["threatType"] for x in respObject["threatLists"]]
        
        return []

    def getupdateforthreat(self, threat, clistate=None):
        reqdict = self.__reqobj.copy()
        reqdict['listUpdateRequests'][0]['threatType'] = threat
        if not clistate == None:
            reqdict['listUpdateRequests'][0]['state'] = clistate

        r = requests.post("https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=" + self.__apikey, json=reqdict)
        if r.status_code < 400:
            return responseobjects.ListUpdateResponse(r.json())

        print r.text
        return None
        
        # URL / EXECUTABLE / IP_RANGE