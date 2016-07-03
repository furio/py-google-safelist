import plyvel
import hashlib
import base64

class ThreatStore(object):
    def __init__(self,dbpath,dbtypes):
        self.__dbpointers = {}
        for x in dbtypes:
            self.__dbpointers[x] = plyvel.DB(dbpath + '/' + x, create_if_missing=True)
      
        self.__dbpointers['KEEPER'] = plyvel.DB(dbpath + '/master-records', create_if_missing=True)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        for key in self.__dbpointers.keys():
            self.__dbpointers[key].close()

    def dbs(self):
        return self.__dbpointers.keys()

    def get(self,store,key):
        return self.__dbpointers[store].fetch(str(key))

    def exist(self,store,key):
        return self.__dbpointers[store].exists(str(key))

    def set(self,store,key,val=''):
        self.__dbpointers[store].put(str(key),str(val))

    def delete(self,store,key):
        self.__dbpointers[store].delete(str(key))

    def keyschecksum(self,store,baseencoded=False):
        keys = []
        for key,val in self.__dbpointers[store]:
            keys.extend(key)

        hashdata = hashlib.sha256(b''.join(keys)).digest()
        if baseencoded:
            return base64.b64encode(hashdata)
        else:
            return hashdata
        