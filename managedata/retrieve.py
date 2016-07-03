import threading

def __addandremdata(threatname, tstore, data):
    remindices = []
    addhashes = []
    for resp in data.responses:
        for addobj in resp.additions:
            for x in addobj.hashes:
                addhashes.extend(x.hashes)
        for remobj in resp.removals:
            for y in remobj.indices:
                remindices.extend(y.indices)

    print "Hashes["+threatname+"] " + str(addhashes)
    print "Indices["+threatname+"] " + str(remindices)

    # Modify store
    tstore.removeat(threatname, remindices)
    for newhash in addhashes:
        tstore.set(threatname, newhash)

def __worker(threatname, stopevent, tstore, reqclass):
    while(not stopevent.is_set()):
        print "Working for: " + threatname
        #
        lastclistate = tstore.get('KEEPER',threatname + ':lastclistate')
        googlechecksum = None
        #
        while True:
            data = reqclass.getupdateforthreat(threatname, lastclistate)
            if data is not None:
                if lastclistate != data.responses[-1].client['state']:
                    __addandremdata(threatname,tstore,data)

                    lastclistate = data.responses[-1].client['state']
                    googlechecksum = data.responses[-1].client['checksum']['sha256']

                    dbchecksum = tstore.keyschecksum(threatname, True)

                    print "Checksum["+threatname+"] " + googlechecksum + " || " + dbchecksum
                    if dbchecksum == googlechecksum:
                        tstore.set('KEEPER',threatname + ':lastclistate', lastclistate)
                        tstore.set('KEEPER',threatname + ':checksum', dbchecksum)
                    else:
                        lastclistate = None
                        tstore.delete('KEEPER',threatname + ':lastclistate')
                        tstore.delete('KEEPER',threatname + ':checksum')
                        tstore.truncate(threatname)                                                                  

                    stopevent.wait(data.nextcheck / 1000)
                else:
                    # Should be backoff here
                    stopevent.wait(5)
                    break
            else:
                # Should be backoff here
                stopevent.wait(5)
                break 

# Many workers as dbs
class ProcessingDataFromGoogle(object):
    def __init__(self, dbptr, threats, requestclass):
        self.__database = dbptr
        self.__threats = threats
        self.__reqclass = requestclass
        self.__workers = []
        
    def __enter__(self):
        for threat in self.__threats:
            tevent = threading.Event()
            t = threading.Thread(target=__worker, args=(threat, tevent, self.__database, self.__reqclass))
            self.__workers.append((t, tevent))
            t.daemon = True
            t.start()
    
    def __exit__(self, exception_type, exception_value, traceback):
        for runningthreads in self.__workers:
            runningthreads[1].stop()

    def join(self):
        for runningthreads in self.__workers:
            runningthreads[0].join()
      