import urlhashes
import base64
import time

# Prefix is fixed now... should be changed to store specific
__PREFIXLEN__ = 4


class UrlHashState(object):
    def __init__(self,threats,tstore,cache,apimanager):
        self.__threats = threats
        self.__tstore = tstore
        self.__cache = cache
        self.__apimanager = apimanager
        self.__nextrequest = int(time.time())

    # https://developers.google.com/safe-browsing/v4/caching
    # negative cache for no "matches"
    # if db returned smth then check the cache
    
    def isUrlBlocked(self,url):
        hashesofurl = self.__getUrlHashes(url)

        print "[CHECKER] Hashes: " + str(hashesofurl)

        # Check if the cache has something
        cachestatus = self.__checkCache(hashesofurl)
        if cachestatus[0] is False:
            return True

        # From db
        possibledbthreats = self.__checkLocaldb(cachestatus[1])
        print "[CHECKER] DB matches: " + str( len(possibledbthreats) )
        if len(possibledbthreats) == 0:
            possibledbthreats = [ (self.__threats[0], x) for x in hashesofurl]
            # return False
        
        # Can i call G 
        if self.__nextrequest > int(time.time()):
            return False

        gcall = self.__collectFromGoogle(possibledbthreats)
        if gcall is None:
            # backoff
            return False

        if not gcall is True:
            return {}

        return gcall
        # Call getattr
        # store
        # return


        # return False

    def __collectFromGoogle(self,tuplesthreathash):
        print tuplesthreathash

        threats = set()
        prefixes = []

        for tupleth in tuplesthreathash:
            threats.add(tupleth[0])
            prefixes.append(base64.b64encode(tupleth[1][:__PREFIXLEN__]))

        threats = list(threats)

        threatsandstates = []
        for threat in threats:
            if (self.__tstore.exist('KEEPER',threat + ':lastclistate')):
                threatsandstates.append((threat, self.__tstore.get('KEEPER',threat + ':lastclistate')))

        if len(threatsandstates) == 0:
            return {}

        print "[CHECKER] Sending request for : " + str( threatsandstates ) + " and " + str(len(prefixes)) + " prefixes"
        return self.__apimanager.getthreatspecific(threatsandstates,prefixes)
        

    def __getUrlHashes(self,url):
        hashgen = urlhashes.URL(url)
        return [uhash for uhash in hashgen.hashes]

    def __checkCache(self, hashesofurl):
        possiblethreats = []

        for urlhash in hashesofurl:
            if self.__cache.get(base64.b64encode(urlhash[:__PREFIXLEN__])) is not None:
                if self.__cache.get(base64.b64encode(urlhash)) is not None:
                    return (False, [])
            else:
                possiblethreats.append(urlhash)

        return (True,possiblethreats)

    def __checkLocaldb(self, hashesofurl):
        possiblethreats = []

        for threat in self.__threats:
            for urlhash in hashesofurl:
                if self.__tstore.exist(threat,urlhash[:__PREFIXLEN__]):
                    possiblethreats.append((threat,urlhash))

        return possiblethreats