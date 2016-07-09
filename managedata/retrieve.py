import threading
import random 

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

        print "["+threatname+"] Prefixes " + str(prefixlen)
        print "["+threatname+"] Hashes " + str(len(addhashes))
        print "["+threatname+"] Indices " + str(len(remindices))

        # Modify store
        if len(remindices) > 0:
            print "["+threatname+"] Modifying indices"
            tstore.removeat(threatname, remindices)

        if len(addhashes) > 0:
            print "["+threatname+"] Modifying hashes"
            tstore.putsKeys(threatname, addhashes)

        if len(prefixlen) > 0:
            print "["+threatname+"] Modifying prefixes"
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
                print "["+threatname+"] Received data"
                if data is not None:
                    # reset backoff
                    failedbackoff = 0
                    
                    # parse data
                    if lastclistate != data.responses[-1].client['state']:
                        self.__addandremdata(threatname,tstore,data)

                        lastclistate = data.responses[-1].client['state']
                        googlechecksum = data.responses[-1].client['checksum']['sha256']

                        dbchecksum = tstore.keyschecksum(threatname, True)

                        print "["+threatname+"] Checksums google/us: " + googlechecksum + " || " + dbchecksum
                        if dbchecksum == googlechecksum:
                            tstore.set('KEEPER',threatname + ':lastclistate', lastclistate)
                            tstore.set('KEEPER',threatname + ':checksum', dbchecksum)
                        else:
                            print "["+threatname+"] Destroyin db"
                            lastclistate = None
                            tstore.delete('KEEPER',threatname + ':lastclistate')
                            tstore.delete('KEEPER',threatname + ':checksum')
                            tstore.delete('KEEPER',threatname + ':prefixlen')
                            tstore.truncate(threatname)                                                                  

                        # Sleep
                        print "["+threatname+"][DONE] Sleep for " + str(data.nextcheck)
                        stopevent.wait(data.nextcheck * __SPEEDFACTOR__ if self.__speedbreak else data.nextcheck)
                    else:
                        print "["+threatname+"][DONE] Clistate is the same. Sleep for " + str(data.nextcheck)
                        stopevent.wait(data.nextcheck * __SPEEDFACTOR__ if self.__speedbreak else data.nextcheck)
                        break
                else:
                    # Should backoff here
                    sleeptime = min((2**(failedbackoff) * 15 * 60 * (random.uniform(0, 1) + 1)), 24*60*60)
                    print "["+threatname+"][DONE] Empty data. Sleep for " + str(sleeptime)
                    
                    stopevent.wait(sleeptime * __SPEEDFACTOR__ if self.__speedbreak else sleeptime)
                    if ( failedbackoff <= 8):
                        failedbackoff = failedbackoff + 1

                    break             
      