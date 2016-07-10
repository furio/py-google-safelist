import base64

class UpdateResponseHashes(object):
    def __init__(self, jsoninput):
        rawobject = jsoninput["rawHashes"]
        prefixlen = rawobject["prefixSize"]
        rawhashes = rawobject["rawHashes"]
        rawhashes = base64.b64decode(rawhashes)

        if not (len(rawhashes)%prefixlen) == 0:
            raise IndexError("Raw hashes mismatch on prefixes", rawhashes, prefixlen)

        self.prefix = prefixlen
        self.hashes = []

        while not len(rawhashes) == 0:
            self.hashes.append(rawhashes[:prefixlen])
            rawhashes = rawhashes[prefixlen:]
    
    def __str__(self):
        strobj = ""
        strobj += "Prefix: " + str(self.prefix) + ", "
        strobj += "Hashes: " + str(self.hashes) + "\n"
        return strobj

class UpdateResponseIndices(object):
    def __init__(self, jsoninput):
        if not jsoninput["compressionType"] == "RAW":
            raise ValueError("Only RAW compression supported")

        self.indices = jsoninput["rawIndices"]['indices']
    
    def __str__(self):
        strobj = ""
        strobj += "Indices: " + str(self.indices) + "\n"
        return strobj        

class UpdateThreatSet(object):
    def __init__(self, jsoninput):
        if not jsoninput["compressionType"] == "RAW":
            raise ValueError("Only RAW compression supported")

        self.hashes = []
        self.indices = []

        if jsoninput.has_key('rawHashes'):
            self.hashes.append(UpdateResponseHashes(jsoninput))

        if jsoninput.has_key('rawIndices'):
            self.indices.append(UpdateResponseIndices(jsoninput))

    def __str__(self):
        strobj = ""
        strobj += "Hashes: " + "".join(["\n\t" + str(x) for x in self.hashes])
        strobj += "Indices: " + "".join(["\n\t" + str(x) for x in self.indices])
        return strobj


class UpdateResponse(object):
    def __init__(self, jsonresponse):
        self.__parse(jsonresponse)

    def __parse(self, jsonresponse):
        if jsonresponse['responseType'] == "RESPONSE_TYPE_UNSPECIFIED":
            raise KeyError("Key listUpdateResponses not valid", jsonresponse)

        self.responsetype = jsonresponse['responseType']
        self.threattype = jsonresponse['threatType']
        self.platformtype = jsonresponse['platformType']
        self.client = {"state": jsonresponse['newClientState'], "checksum": jsonresponse['checksum'] }
        self.additions = []
        self.removals = []
        if jsonresponse.has_key('additions'):
            self.additions = [UpdateThreatSet(x) for x in jsonresponse['additions']]
        if jsonresponse.has_key('removals'):
            self.removals = [UpdateThreatSet(x) for x in jsonresponse['removals']]

    def __str__(self):
        strobj = ""
        strobj += "ResponseType: " + str(self.responsetype) + ", "
        strobj += "ThreatType: " + str(self.threattype) + ", "
        strobj += "PlatformType: " + str(self.platformtype) + ", "
        strobj += "ClientStatus: " + str(self.client) + "\n"
        strobj += "Additions: " + "".join(["\n\t" + str(x) for x in self.additions])
        strobj += "Removals: " + "".join(["\n\t" + str(x) for x in self.removals])
        return strobj

class ListUpdateResponse(object):
    def __init__(self, jsonobject):
        if not jsonobject.has_key('listUpdateResponses'):
            raise KeyError("Key listUpdateResponses not found", jsonobject)

        self.nextcheck = int(float(jsonobject['minimumWaitDuration'][:-1])) + 1
        self.responses = [UpdateResponse(x) for x in jsonobject['listUpdateResponses']]
    
    def __str__(self):
        strobj = ""
        strobj += "Retry: " + str(self.nextcheck) + ", "
        strobj += "Updates: " + "".join(["\n\t" + str(x) for x in self.responses])
        return strobj
