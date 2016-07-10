import base64

class MetadataEntryResponse(object):
    def __init__(self, jsonobject):
        self.key = None
        self.value = None

        if jsonobject.has_key('key'):
            self.key = base64.b64decode(jsonobject['key']) 

        if jsonobject.has_key('value'):
            self.value = base64.b64decode(jsonobject['value'])

    def __str__(self):
        strobj = ""
        strobj += "Key: " + str(self.key) + ", "
        strobj += "Value: " + str(self.value) + "\n"
        return strobj                  

class ThreatEntryMetadataResponse(object):
    def __init__(self, jsonobject):
        self.entries = []
        
        if jsonobject.has_key('entries'):
            self.entries = [MetadataEntryResponse(x) for x in jsonobject['entries']]

    def __str__(self):
        strobj = ""
        strobj += "Entries: " + "".join(["\n\t" + str(x) for x in self.entries])
        return strobj            

class ThreatEntryResponse(object):
    def __init__(self, jsonobject):
        self.hash = None
        self.url = None
        self.digest = None

        if jsonobject.has_key('hash'):
            self.hash = base64.b64decode(jsonobject['hash'])

        if jsonobject.has_key('url'):
            self.url = jsonobject['url']

        if jsonobject.has_key('digest'):
            self.digest = base64.b64decode(jsonobject['digest'])

    def __str__(self):
        strobj = ""
        strobj += "Hash: " + str(self.hash) + ", "
        strobj += "Url: " + str(self.url) + ", "        
        strobj += "Digest: " + str(self.digest) + "\n"
        return strobj              

class ThreatMatchesResponse(object):
    def __init__(self, jsonobject):
        self.type = []
        self.platform = []
        self.entries = []
        self.threat = None
        self.metadata = None
        self.cache = 0

        if jsonobject.has_key('cacheDuration'):
            self.cache = int(float(jsonobject['cacheDuration'][:-1])) + 1

        if jsonobject.has_key('threatType'):
            self.type = jsonobject['threatType']

        if jsonobject.has_key('platformType'):
            self.platform = jsonobject['platformType']

        if jsonobject.has_key('threatEntryType'):
            self.entries = jsonobject['threatEntryType']

        if jsonobject.has_key('threat'):
            self.threat = ThreatEntryResponse(jsonobject['threat'])

        if jsonobject.has_key('metadata'):
            self.metadata = ThreatEntryMetadataResponse(jsonobject['metadata'])            
    
    def __str__(self):
        strobj = ""
        strobj += "Cache: " + str(self.cache) + ", "
        strobj += "ThreatType: " + str(self.type) + ", "
        strobj += "PlatformType: " + str(self.platform) + ", "
        strobj += "ThreatEntryType: " + str(self.type) + ", "
        strobj += "Threat: " + str(self.threat) + ", "
        strobj += "Metadata: " + str(self.metadata) + "\n"
        return strobj

class FullHashesFindResponse(object):
    def __init__(self, jsonobject):
        self.nextcheck = 1
        self.negativecache = 0
        self.matches = []

        if jsonobject.has_key('minimumWaitDuration'):
            self.nextcheck = int(float(jsonobject['minimumWaitDuration'][:-1])) + 1

        if jsonobject.has_key('negativeCacheDuration'):
            self.negativecache = int(float(jsonobject['negativeCacheDuration'][:-1])) + 1

        if jsonobject.has_key('matches'):
            self.matches = [ThreatMatchesResponse(x) for x in jsonobject['matches']]
                        
    
    def __str__(self):
        strobj = ""
        strobj += "Retry: " + str(self.nextcheck) + ", "
        strobj += "NegativeCache: " + str(self.negativecache) + ", "
        strobj += "Matches: " + "".join(["\n\t" + str(x) for x in self.matches])
        return strobj