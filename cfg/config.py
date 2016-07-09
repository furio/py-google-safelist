import ConfigParser

class Config(object):
    def __init__(self, cfgfile):
        self.__config = ConfigParser.RawConfigParser()
        self.__config.read(cfgfile)

    def getGoogleKey(self):
        return self.__config.get("google","key")
    
    def getGoogleCompany(self):
        return self.__config.get("google","companyname")

    def getGoogleDbSize(self):
        return int(self.__config.get("google","threatsize"))              

    def getRedis(self):
        return {'host': self.__config.get("redis", "host"), 'port': int(self.__config.get("redis", "port")), 'db': int(self.__config.get("redis", "db"))}

    def getLeveldbPath(self):
        return self.__config.get("leveldb", "path")