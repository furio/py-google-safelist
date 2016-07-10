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

        # From db
        possiblethreats = self.__checkLocaldb(hashesofurl)
        uniquepossibethreats = list(set([y for x in possiblethreats.keys() for y in possiblethreats[x]]))
        print "[CHECKER] DB matches: " + str( len(uniquepossibethreats) )
        if len(uniquepossibethreats) == 0:
            uniquepossibethreats = hashesofurl[:]
            for tx in self.__threats:
                possiblethreats[tx] = uniquepossibethreats
            # return False
        
        # Check if the cache has something
        cachestatus, cachehashes = self.__checkCache(uniquepossibethreats)
        print "[CHECKER] Cache status: " + str( cachestatus )
        print "[CHECKER] Cache matches to check: " + str( len(cachehashes) )
        if cachestatus is False:
            return True

        # Can i call GeneratorExit
        print "[CHECKER] Timeout check: " + str( self.__nextrequest ) + " || " +str(int(time.time()))
        if self.__nextrequest > int(time.time()):
            return False

        for tkey in possiblethreats.keys():
            possiblethreats[tkey] = [x for x in possiblethreats[tkey] if x in cachehashes]
            if len(possiblethreats[tkey]) == 0:
                del possiblethreats[tkey]

        print "[CHECKER] Preparing to call G : " + str( possiblethreats )
        gcall = self.__collectFromGoogle(possiblethreats)
        print "[CHECKER] Call G done : " + str( gcall )
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

    def __collectFromGoogle(self, possiblethreats):
        encodedprefixes = set()
        threatsandstates = []

        for tkey in possiblethreats.keys():
            if (self.__tstore.exist('KEEPER',tkey + ':lastclistate')):
                threatsandstates.append((tkey, self.__tstore.get('KEEPER',tkey + ':lastclistate')))

            for vhash in possiblethreats[tkey]:
                encodedprefixes.add(base64.b64encode(vhash[:__PREFIXLEN__]))

        if len(threatsandstates) == 0:
            return {}

        encodedprefixes = list(encodedprefixes)

        print "[CHECKER] Sending request for : " + str( threatsandstates ) + " and " + str(len(encodedprefixes)) + " prefixes"
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
            for urlhash in hashesofurl:
                if self.__tstore.exist(threat,urlhash[:__PREFIXLEN__]):
                    possiblethreats[threat].append(urlhash)

        return possiblethreats