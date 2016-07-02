import unqlite
import hashlib
import base64

class ThreatStore(object):
    def __init__(self,dbpath,dbtypes):
        self.__dbpointers = {}
        for x in dbtypes:
            self.__dbpointers[x] = unqlite.UnQLite(dbpath + '/' + x + ".db")
      
            self.__dbpointers['KEEPER'] = unqlite.UnQLite(dbpath + '/' + "master-rescord" + ".db")

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        for key in self.__dbpointers.keys():
            self.__dbpointers[key].close()

    def dbs(self):
        return self.__dbpointers.keys()

    def get(self,store,key):
        return self.__dbpointers[store].fetch("key" + key)

    def exist(self,store,key):
        return self.__dbpointers[store].exists("key" + key)

    def set(self,store,key,val=''):
        self.__dbpointers[store].store("key" + key,val)

    def delete(self,store,key):
        self.__dbpointers[store].delete("key" + key)

    def keyschecksum(self,store,baseencoded=False):
        hashdata = hashlib.sha256(b''.join([item[0][3:] for item in self.__dbpointers[store]])).digest()
        if baseencoded:
            return base64.b64encode(hashdata)
        else:
            return hashdata
        