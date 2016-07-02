import ConfigParser
import requestsapi
import time
# import sys
# import hashlib
# import base64
import datastore
import os

def getApiKey():
    config = ConfigParser.RawConfigParser()
    config.read("config.cfg")
    return config.get("google","key")

apiRequest = requestsapi.RequestData(getApiKey(), "Furiosoft")
threatList = apiRequest.getthreatlists() 
datalist = []
lastclistate = None
checksums = []

with datastore.ThreatStore(os.path.abspath('./save'),threatList) as tstore:
    for threat in threatList:
        print threat
        datalist = []
        lastclistate = None
        checksums = []
        #
        while True:
            data = apiRequest.getupdateforthreat(threat, lastclistate)
            if data is not None:
                if lastclistate != data.responses[-1].client['state']:
                    lastclistate = data.responses[-1].client['state']
                    checksums.append(data.responses[-1].client['checksum']['sha256'])
                    datalist.append(data)
                    time.sleep(data.nextcheck / 1000)
                else:
                    break
            else:
                break
        #
        if len(datalist) > 0:
            print "Saving" # Here we need to check if smth is already there and indices removals
            for x in datalist:
                for y in x.responses:
                    for z in y.additions:
                        for w in z.hashes:
                            for u in w.hashes:
                                # unqlite not accepting all bytes?
                                tstore.set(threat,u)
                
            tstore.set('KEEPER',threat + ':lastclistate', lastclistate)
            tstore.set('KEEPER',threat + ':checksums', checksums[-1])

            print lastclistate
            print checksums[-1]
            print tstore.keyschecksum(threat, True)

'''
while True:
    sys.stdout.write(str(len(datalist)) + " ")
    data = apiRequest.getupdateforthreat(threatList[0], lastclistate)
    if data is not None:
        if lastclistate != data.responses[-1].client['state']:
            lastclistate = data.responses[-1].client['state']
            checksums.append(data.responses[-1].client['checksum']['sha256'])
            datalist.append(data)
            time.sleep(data.nextcheck / 1000)
        else:
            break
    else:
        break

sys.stdout.write("\n")
sys.stdout.flush()

hasheslist = []
for x in datalist:
    for y in x.responses:
        for z in y.additions:
            for w in z.hashes:
                hasheslist.extend(w.hashes)

print hasheslist[0:10]
sortedlist = sorted(hasheslist)
print sortedlist[0:10]

print "Hashes"
print len(sortedlist)
sha2 = hashlib.sha256(b''.join(sortedlist)).digest()
print "-"
print sha2
print base64.b64decode(lastclistate)
print "-"
print base64.b64encode(sha2)
print lastclistate
print "-"
print checksums
'''

'''
for threat in threatList:
    clistate = None
    outfile = open( "save/save-" + threat + ".p", "wb" )
    sys.stdout.write(threat + ": ")
    for x in xrange(10):
        sys.stdout.write(str(x) + " ")
        data = apiRequest.getupdateforthreat(threat, clistate)
        if data is not None:
            outfile.write(str(data) + "\n\n\n\n\n")
            clistate = data.responses[-1].client['state']
            time.sleep(data.nextcheck / 1000)
        else:
            break

    sys.stdout.write("\n")
    sys.stdout.flush()
    outfile.close()
'''
