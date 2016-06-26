import ConfigParser
import requestsapi
import time
import sys

def getApiKey():
    config = ConfigParser.RawConfigParser()
    config.read("config.cfg")
    return config.get("google","key")

apiRequest = requestsapi.RequestData(getApiKey(), "Furiosoft")
threatList = apiRequest.getthreatlists() 

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

