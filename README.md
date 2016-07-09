Add in path a file named "config.cfg" with content

```
[google]
key=---YOUR-GOOGLE-API-KEY---

[redis]
host=redis
port=6379
db=0

[leveldb]
path=./save
```

Edit in docker-compose.yml the source path for the volume mount
```
        volumes:
            - /Users/furione/git/py-google-safelist:/tmp/py-project
```

Service will be on port 5000
