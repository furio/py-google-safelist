import plyvel
import hashlib
import base64

class ThreatStore(object):
    def __init__(self,dbpath,dbtypes):
        self.__dbpath = dbpath
        self.__dbpointers = {}
        for x in dbtypes:
            self.__dbpointers[x] = self.__createdb(x)
      
        self.__dbpointers['KEEPER'] = self.__createdb('master-records')

    def __createdb(self, dbname):
        return plyvel.DB(self.__dbpath + '/' + dbname, create_if_missing=True)

    def __truncatedb(self, dbname):
        plyvel.destroy_db(self.__dbpath + '/' + dbname)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        for key in self.__dbpointers.keys():
            self.__dbpointers[key].close()

    def dbs(self):
        return self.__dbpointers.keys()

    def removeat(self, store, indices):
        if len(indices) > 0:
            pos = 0
            remkeys = []
            for key in self.__dbpointers[store].iterator(include_value=False):
                if pos in indices:
                    remkeys.append(key)
                pos = pos + 1
            for key in remkeys:
                self.delete(store,key)

    def get(self,store,key):
        return self.__dbpointers[store].get(str(key))

    def exist(self,store,key):
        return self.get(store,key) is not None

    def set(self,store,key,val=''):
        self.__dbpointers[store].put(str(key),str(val))

    def puts(self,store,tuplelist):
        with self.__dbpointers[store].write_batch() as writer:
            for keyandval in tuplelist:
                writer.put(str(keyandval[0]),str(keyandval[1]))

    def putsKeys(self,store,keylist,val=''):
        with self.__dbpointers[store].write_batch() as writer:
            for key in keylist:
                writer.put(str(key),str(val))

    def delete(self,store,key):
        self.__dbpointers[store].delete(str(key))

    def keyschecksum(self,store,baseencoded=False):
        keys = []
        for key in self.__dbpointers[store].iterator(include_value=False):
            keys.extend(key)

        hashdata = hashlib.sha256(b''.join(keys)).digest()
        if baseencoded:
            return base64.b64encode(hashdata)
        else:
            return hashdata

    def truncate(self,store):
        # Possible KABOOM
        self.__dbpointers[store].close()
        self.__truncatedb(store)
        self.__dbpointers[store] = self.__createdb(store)
