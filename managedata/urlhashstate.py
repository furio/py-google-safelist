import urlhashes
import base64
import time
import logging
from datastore import KeeperStore

# Prefix fo cache checks/sets
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
        
        logging.info("[CHECKER] Hashes: %s", str(len(hashesofurl)))

        # From db
        possiblethreats = self.__checkLocaldb(hashesofurl)
        uniquepossibethreats = list(set([y for x in possiblethreats.keys() for y in possiblethreats[x]]))
        logging.info("[CHECKER] DB matches: %s", str( len(uniquepossibethreats) ))
        if len(uniquepossibethreats) == 0:
            return False
        
        # Check if the cache has something
        cachestatus, cachehashes = self.__checkCache(uniquepossibethreats)
        logging.info("[CHECKER] Cache status: %s", str( cachestatus ))
        logging.info("[CHECKER] Cache matches to check: %s", str( len(cachehashes) ))
        if cachestatus is False:
            return True

        # Can i call GeneratorExit
        logging.info("[CHECKER] Timeout check: %s || %s", str( self.__nextrequest ), str(int(time.time())) )
        if self.__nextrequest > int(time.time()):
            return False

        for tkey in possiblethreats.keys():
            possiblethreats[tkey] = [x for x in possiblethreats[tkey] if x in cachehashes]
            if len(possiblethreats[tkey]) == 0:
                del possiblethreats[tkey]

        logging.info("[CHECKER] Preparing to call G : %s", str( possiblethreats ))
        gcall = self.__collectFromGoogle(possiblethreats)
        logging.info("[CHECKER] Call G done ")
        if gcall is None:
            return False

        isthreat = self.__updateLocalCache(gcall, cachehashes)
        
        return isthreat

    def __updateLocalCache(self, gresult, hashes):
        self.__nextrequest = int(time.time()) + gresult.nextcheck
        isthreat = False

        for x in hashes:
            self.__cache.setex(base64.b64encode(x[:__PREFIXLEN__]), gresult.negativecache + 1, '')

        if len(gresult.matches) == 0:
            return isthreat

        
        for mx in gresult.matches:
            if mx.threat is not None and mx.threat.hash in hashes:
                isthreat = True
                self.__cache.setex(base64.b64encode(mx.threat.hash), mx.cache + 1, '')

        return isthreat

    def __collectFromGoogle(self, possiblethreats):
        encodedprefixes = set()
        threatsandstates = []

        for tkey in possiblethreats.keys():
            if KeeperStore.hasLastClistate(self.__tstore, tkey):
                threatsandstates.append((tkey, KeeperStore.getLastClistate(self.__tstore, tkey)))

            for vhash in possiblethreats[tkey]:
                encodedprefixes.add(base64.b64encode(vhash[:__PREFIXLEN__]))

        if len(threatsandstates) == 0:
            return {}

        encodedprefixes = list(encodedprefixes)

        logging.info("[CHECKER] Sending request for : %s and %s prefixes", str( threatsandstates ), str(len(encodedprefixes)))
        return self.__apimanager.getthreatspecific(threatsandstates,encodedprefixes)
        

    def __getUrlHashes(self,url):
        hashgen = urlhashes.URL(url)
        return [uhash for uhash in hashgen.hashes]

    def __checkCache(self, hashesofurl):
        possiblethreats = []

        for urlhash in hashesofurl:
            if self.__cache.get(base64.b64encode(urlhash[:__PREFIXLEN__])) is not None:
                if self.__cache.get(base64.b64encode(urlhash)) is not None:
                    return False, []
            else:
                possiblethreats.append(urlhash)

        return True,possiblethreats

    def __checkLocaldb(self, hashesofurl):
        possiblethreats = {}

        for threat in self.__threats:
            possiblethreats.setdefault(threat,[])

            possiblelens = KeeperStore.getLastClistate(self.__tstore, threat)
            if len(possiblelens) == 0:
                possiblelens = set([__PREFIXLEN__])

            for urlhash in hashesofurl:
                for pfxlen in possiblelens:
                    if self.__tstore.exist(threat,urlhash[:pfxlen]):
                        possiblethreats[threat].append(urlhash)

        return possiblethreats
