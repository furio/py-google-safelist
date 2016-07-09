import requestsapi
import datastore
import os
import managedata
import cfg
import redis
from flask import Flask
    
# Cfg
config = cfg.Config(os.path.abspath('./config.cfg'))
dbpath = os.path.abspath(config.getLeveldbPath())
rediscfg = config.getRedis()

# Api Class
apiRequest = requestsapi.RequestData(config.getGoogleKey(), "Furiosoft", 64000)

# ThreatList (might be config)
threatList = apiRequest.getthreatlists()[0:2]

# Store(s)
rediscli = redis.StrictRedis(host=rediscfg['host'], port=rediscfg['port'], db=rediscfg['db'])
tstore = datastore.ThreatStore(dbpath,threatList)
googleproc = managedata.ProcessingDataFromGoogle(tstore, threatList, apiRequest)

# Flask
app = Flask(__name__)

# Routes definitions
@app.route("/")
def hello():
    return "Hello World!"

if __name__ == "__main__":
    # Test
    googleproc.start()
    app.run(host="0.0.0.0")