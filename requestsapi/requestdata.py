import requests
import responseobjects

__CLIENT_VERSION__ = "0.1.0"
__ANY_PLATFORM__ = "ANY_PLATFORM"
__THREAT_URL__ = "URL"

class RequestData(object):
    def __init__(self,apikey,companyname,maxsize=4096):
        self.__apikey = apikey 
        self.__reqobj = {
                        "client": { "clientId": companyname, "clientVersion":  __CLIENT_VERSION__},
                        "listUpdateRequests": [
                            {"threatType": "", "platformType": __ANY_PLATFORM__, "threatEntryType": __THREAT_URL__, 
                            "constraints": { "maxUpdateEntries": maxsize, "region": "US", "supportedCompressions": ["RAW"]}}
                        ]}
        self.__detailobj = {
                        "client": { "clientId": companyname, "clientVersion":  __CLIENT_VERSION__},
                        "clientStates": [],
                        "threatInfo": {
                                "threatTypes":      [],
                                "platformTypes":    [__ANY_PLATFORM__],
                                "threatEntryTypes": [__THREAT_URL__],
                                "threatEntries": []
                            }                        
                        }

    def getthreatlists(self):
        r = requests.get("https://safebrowsing.googleapis.com/v4/threatLists", {'key': self.__apikey})
        if r.status_code < 400:
            respObject = r.json()
            return [x["threatType"] for x in respObject["threatLists"]]
        
        return []

    def getupdateforthreat(self, threat, clistate=None):
        "Accept a 'threatname'' and optional 'clistate'"

        reqdict = self.__reqobj.copy()
        reqdict['listUpdateRequests'][0]['threatType'] = threat
        if not clistate == None:
            reqdict['listUpdateRequests'][0]['state'] = clistate

        r = requests.post("https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?key=" + self.__apikey, json=reqdict)
        if r.status_code < 400:
            return responseobjects.ListUpdateResponse(r.json())

        return None

    
    def getthreatspecific(self, threatandstates, hashes):
        "Accept a [(threat,clistate)] and []"

        reqdict = self.__detailobj.copy()
        for tands in threatandstates:
            reqdict['clientStates'].append(tands[1])
            reqdict['threatInfo']['threatTypes'].append(tands[0])

        for hashprefix in hashes:
            reqdict['threatInfo']['threatEntries'].append({"hash": hashprefix})

        r = requests.post("https://safebrowsing.googleapis.com/v4/fullHashes:find?key=" + self.__apikey, json=reqdict)

        # print r.text

        if r.status_code < 400:
            return r.json()

        return None        
        
        # URL / EXECUTABLE / IP_RANGE