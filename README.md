# Python service for Google Safe Browsing APIs (v4)

This utility allows you to store locally and check an URL against  
the Google safe browsing api (v4) https://developers.google.com/safe-browsing/v4/

The service can be used via web on port 5000 by doing a POST to /url-check
passing as body a JSON with similar content:
```
{"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"}
```

This service is a just a pet project, cannot be called production ready or anything.
You're free to try/use it, but I reccomend you to use the Google official implementation at: https://github.com/google/safebrowsing/

# Setup

To use this package you must obtain an *API key* from the
[Google Developer Console](https://console.developers.google.com/).

Once you've the *API key* add in path "conf-files/" a file named "config.cfg" with content like:
```
[google]
key=---YOUR-GOOGLE-API-KEY---
companyname=--YOUR-COMPANY--
threatsize=4096

[redis]
host=redis
port=6379
db=0

[leveldb]
path=/opt/app/save
```

You'll need also a Redis server, it'll be used as a cache for soring result of queries with ttl.

## Docker

### Testing

In docker-compose.yml tha variable HOST_SRC_PATH is used to determine where on the host the app is. 

Once up you can enter the python container and start the server with

```
docker exec -ti pygooglesafelist_pydbg_1 /bin/bash
cd /tmp/py-project
python main-py
```

### Production

In ```docker-release/``` there is a docker-compose.xml file, it will expose the service on port 5000.
The system will create a datavolume to save leveldb data and require an external datavolume named ```pysafe-config``` to contain the config files
