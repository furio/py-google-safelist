# Python service for Google Safe Browsing APIs (v4)

This utility allows you to store locally and interrogate 
the Google safe browsing api (v4) https://developers.google.com/safe-browsing/v4/

The service can be interrogated via web on port 5000 by doing a POST to /url-check
passing as body with a JSON fromatted as
```
{"url":"http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/MALWARE/URL/"}
```

This service is a pet project, cannot be called production ready or anything.
You're free to try it, but I reccomend you to use the Google official implementation at: https://github.com/google/safebrowsing/

# Setup

To use this package you must obtain an *API key* from the
[Google Developer Console](https://console.developers.google.com/).

Once you've the *API key* add in path a file named "config.cfg" with content like:
```
[google]
key=---YOUR-GOOGLE-API-KEY---
companyname=--YUOR-COMPANY--
threatsize=4096

[redis]
host=redis
port=6379
db=0

[leveldb]
path=./save
```

You'll need also a Redis server (as per config section).

## Docker

If you want there is a docker-compose.yml file in the root that should be edited with 
the appropriate source path

Edit in docker-compose.yml the source path for the volume mount
```
        volumes:
            - /Users/furione/git/py-google-safelist:/tmp/py-project
```

Once up you can enter the python container and start the server with

```
docker exec -ti pygooglesafelist_pydbg_1 /bin/bash
cd /tmp/py-project
python main-py
```

You can use the Dockerfile provided to make also an image with the source already inside and autorun it