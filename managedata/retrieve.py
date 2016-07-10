import threading
import random 
import logging

# Less than one could make Google ban you, use for testing only
__SPEEDFACTOR__ = 0.01

# Many workers as dbs
class ProcessingDataFromGoogle(object):
    def __init__(self, dbptr, threats, requestclass):
        self.__database = dbptr
        self.__threats = threats
        self.__reqclass = requestclass
        self.__speedbreak = True
        self.__workers = []
        
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exception_type, exception_value, traceback):
        self.stop()

    def start(self):
        for threat in self.__threats:
            tevent = threading.Event()
            t = threading.Thread(target=self.__worker, args=(threat, tevent, self.__database, self.__reqclass))
            self.__workers.append((t, tevent))
            t.daemon = True
            t.start()
    
    def stop(self):
        for runningthreads in self.__workers:
            runningthreads[1].set()

    def __addandremdata(self, threatname, tstore, data):
        remindices = []
        addhashes = []
        prefixlen = set()

        for resp in data.responses:
            for addobj in resp.additions:
                for x in addobj.hashes:
                    prefixlen.add(x.prefix)
                    addhashes.extend(x.hashes)
            for remobj in resp.removals:
                for y in remobj.indices:
                    remindices.extend(y.indices)

        prefixlen = list(prefixlen)

        logging.info("[%s] Prefixes %s", threatname, str(prefixlen))
        logging.info("[%s] Hashes %s", threatname, str(len(addhashes)))
        logging.info("[%s] Indices %s", threatname, str(len(remindices)))

        # Modify store
        if len(remindices) > 0:
            logging.info("[%s] Modifying indices", threatname)
            tstore.removeat(threatname, remindices)

        if len(addhashes) > 0:
            logging.info("[%s] Modifying hashes", threatname)
            tstore.putsKeys(threatname, addhashes)

        if len(prefixlen) > 0:
            logging.info("[%s] Modifying prefixes", threatname)
            tstore.set('KEEPER',threatname + ':prefixlen', str(list(prefixlen)))

    def __worker(self, threatname, stopevent, tstore, reqclass):
        failedbackoff = 0

        while(not stopevent.is_set()):
            #
            lastclistate = tstore.get('KEEPER',threatname + ':lastclistate')
            googlechecksum = None
            #
            while True:
                data = reqclass.getupdateforthreat(threatname, lastclistate)
                logging.info("[%s] Received data", threatname)
                if data is not None:
                    # reset backoff
                    failedbackoff = 0
                    
                    # parse data
                    if lastclistate != data.responses[-1].client['state']:
                        self.__addandremdata(threatname,tstore,data)

                        lastclistate = data.responses[-1].client['state']
                        googlechecksum = data.responses[-1].client['checksum']['sha256']

                        dbchecksum = tstore.keyschecksum(threatname, True)

                        logging.info("[%s] Checksums google/us: %s || %s", threatname, googlechecksum, dbchecksum)
                        if dbchecksum == googlechecksum:
                            tstore.set('KEEPER',threatname + ':lastclistate', lastclistate)
                            tstore.set('KEEPER',threatname + ':checksum', dbchecksum)
                        else:
                            logging.info("[%s] Destroyin db", threatname)
                            lastclistate = None
                            tstore.delete('KEEPER',threatname + ':lastclistate')
                            tstore.delete('KEEPER',threatname + ':checksum')
                            tstore.delete('KEEPER',threatname + ':prefixlen')
                            tstore.truncate(threatname)                                                                  

                        # Sleep
                        logging.info("[%s][DONE] Sleep for %s", threatname, str(data.nextcheck))
                        stopevent.wait(data.nextcheck * __SPEEDFACTOR__ if self.__speedbreak else data.nextcheck)
                    else:
                        logging.info("[%s][DONE] Clistate is the same. Sleep for %s", threatname, str(data.nextcheck))
                        stopevent.wait(data.nextcheck * __SPEEDFACTOR__ if self.__speedbreak else data.nextcheck)
                        break
                else:
                    # Should backoff here
                    sleeptime = min((2**(failedbackoff) * 15 * 60 * (random.uniform(0, 1) + 1)), 24*60*60)
                    logging.info("[%s][DONE] Empty data. Sleep for %s", threatname, str(sleeptime))
                    
                    stopevent.wait(sleeptime * __SPEEDFACTOR__ if self.__speedbreak else sleeptime)
                    if ( failedbackoff <= 8):
                        failedbackoff = failedbackoff + 1

                    break             
      