import threading



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
            t = threading.Thread(target=self.__worker, args=(threat, tevent, self.__database, self.__reqclass))
            self.__workers.append((t, tevent))
            t.daemon = True
            t.start()
    
    def __exit__(self, exception_type, exception_value, traceback):
        for runningthreads in self.__workers:
            runningthreads[1].set()

    def wait(self):
        print self.__workers
        for runningthreads in self.__workers:
            print runningthreads
            runningthreads[0].join()

    def __addandremdata(self, threatname, tstore, data):
        remindices = []
        addhashes = []
        for resp in data.responses:
            for addobj in resp.additions:
                for x in addobj.hashes:
                    addhashes.extend(x.hashes)
            for remobj in resp.removals:
                for y in remobj.indices:
                    remindices.extend(y.indices)

        print "Hashes["+threatname+"] " + str(len(addhashes))
        print "Indices["+threatname+"] " + str(len(remindices))

        # Modify store
        print "Modifying indices["+threatname+"]"
        tstore.removeat(threatname, remindices)
        print "Modifying hahses["+threatname+"]"
        tstore.putsKeys(threatname, addhashes)

    def __worker(self, threatname, stopevent, tstore, reqclass):
        while(not stopevent.is_set()):
            print "Working for: " + threatname
            #
            lastclistate = tstore.get('KEEPER',threatname + ':lastclistate')
            googlechecksum = None
            #
            while True:
                print "Getting data for " + threatname
                data = reqclass.getupdateforthreat(threatname, lastclistate)
                print "Received data for " + threatname
                if data is not None:
                    print "Parsing data for " + threatname
                    if lastclistate != data.responses[-1].client['state']:
                        self.__addandremdata(threatname,tstore,data)

                        lastclistate = data.responses[-1].client['state']
                        googlechecksum = data.responses[-1].client['checksum']['sha256']

                        dbchecksum = tstore.keyschecksum(threatname, True)

                        print "Checksum["+threatname+"] " + googlechecksum + " || " + dbchecksum
                        if dbchecksum == googlechecksum:
                            tstore.set('KEEPER',threatname + ':lastclistate', lastclistate)
                            tstore.set('KEEPER',threatname + ':checksum', dbchecksum)
                        else:
                            print "Destroyin db for " + threatname
                            lastclistate = None
                            tstore.delete('KEEPER',threatname + ':lastclistate')
                            tstore.delete('KEEPER',threatname + ':checksum')
                            tstore.truncate(threatname)                                                                  

                        stopevent.wait(data.nextcheck / 1000)
                    else:
                        # Should be backoff here
                        print "Clistate is the same " + threatname
                        stopevent.wait(10)
                        break
                else:
                    # Should be backoff here
                    print "Empty data " + threatname
                    stopevent.wait(10)
                    break             
      