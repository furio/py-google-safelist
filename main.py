import requests
import ConfigParser
import responseobjects
import requestsapi

def getApiKey():
    config = ConfigParser.RawConfigParser()
    config.read("config.cfg")
    return config.get("google","key")

apiRequest = requestsapi.RequestData(getApiKey(), "Furiosoft")
threatList = apiRequest.getthreatlists() 
print threatList
print apiRequest.getupdateforthreat(threatList[0])