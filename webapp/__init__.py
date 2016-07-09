import requestsapi
import datastore
import os
import managedata
import cfg
import redis

# Cfg
config = cfg.Config(os.path.abspath('./config.cfg'))
dbpath = os.path.abspath(config.getLeveldbPath())
rediscfg = config.getRedis()

# Api Class
apiRequest = requestsapi.RequestData(config.getGoogleKey(), config.getGoogleCompany(), config.getGoogleDbSize())

# ThreatList (might be config)
threatlist = apiRequest.getthreatlists()[0:2]

# Store(s)
rediscli = redis.StrictRedis(host=rediscfg['host'], port=rediscfg['port'], db=rediscfg['db'])
tstore = datastore.ThreatStore(dbpath,threatlist)
googleproc = managedata.ProcessingDataFromGoogle(tstore, threatlist, apiRequest)
urlmanager = managedata.UrlHashState(threatlist, tstore, rediscli, apiRequest)

# Flask
from flask import Flask
app = Flask(__name__)

# Circular stuff
import routes