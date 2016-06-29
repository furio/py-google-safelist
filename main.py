import ConfigParser
import requestsapi
import time
import sys
import hashlib
import base64

def getApiKey():
    config = ConfigParser.RawConfigParser()
    config.read("config.cfg")
    return config.get("google","key")

apiRequest = requestsapi.RequestData(getApiKey(), "Furiosoft")
threatList = apiRequest.getthreatlists() 
datalist = []
lastclistate = None

for x in xrange(3):
    sys.stdout.write(str(x) + " ")
    data = apiRequest.getupdateforthreat(threatList[0], lastclistate)
    if data is not None:
        lastclistate = data.responses[-1].client['state']
        time.sleep(data.nextcheck / 1000)
    else:
        break

sys.stdout.write("\n")
sys.stdout.flush()

hasheslist = []
for x in datalist:
    for y in x.responses:
        for z in y.additions:
            for w in z.hashes:
                print w.hashes
                hasheslist.extend(w.hashes)

hasheslist.sort()

print "Hashes"
print len(hasheslist)
sha2 = hashlib.sha256("".join(hasheslist)).digest()
print "-"
print sha2
print base64.b64decode(lastclistate)
print "-"
print base64.b64encode(sha2)
print lastclistate


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
