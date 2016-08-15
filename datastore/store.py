import plyvel
import hashlib
import base64
import pickle
import logging
import binascii

__DEFAULT_VAL__ = '' 

class ThreatStore(object):
    def __init__(self,dbpath,dbtypes):
        self.__dbpath = dbpath
        self.__dbpointers = {}
        for x in dbtypes:
            self.__dbpointers[x] = self.__createdb(x)
      
        self.__dbpointers['KEEPER'] = self.__createdb('master-records')

    @staticmethod
    def __serializeKey(val):
        return str(val)

    @staticmethod
    def __serializeValue(val):
        return pickle.dumps(val)

    @staticmethod 
    def __unserializeValue(val):
        return pickle.loads(val)

    def __createdb(self, dbname):
        return plyvel.DB(self.__dbpath + '/' + dbname, create_if_missing=True)

    def __truncatedb(self, dbname):
        plyvel.destroy_db(self.__dbpath + '/' + dbname)

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def close(self):
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

    def __get(self,store,key):
        return self.__dbpointers[store].get(ThreatStore.__serializeKey(key))

    def get(self,store,key):
        simpleget = self.__get(store,key)
        
        if simpleget is not None:
            try:
                simpleget = ThreatStore.__unserializeValue(simpleget)
            except:
                logging.error("[LevelDB][%s] Unwrapping value for key %s failed, returning default.", store, binascii.hexlify(key))
                simpleget = __DEFAULT_VAL__           

        return simpleget        

    def exist(self,store,key):
        return self.get(store,key) is not None

    def __set(self,store,key,val):
        self.__dbpointers[store].put(ThreatStore.__serializeKey(key),ThreatStore.__serializeValue(val))

    def set(self,store,key,val=__DEFAULT_VAL__):
        if val is None:
            val = __DEFAULT_VAL__
        
        self.__set(store,key,val)    

    def puts(self,store,tuplelist):
        with self.__dbpointers[store].write_batch() as writer:
            for keyandval in tuplelist:
                writer.put(ThreatStore.__serializeKey(keyandval[0]),ThreatStore.__serializeValue(keyandval[1]))

    def putsKeys(self,store,keylist,val=__DEFAULT_VAL__):
        with self.__dbpointers[store].write_batch() as writer:
            for key in keylist:
                if val is None:
                    val = __DEFAULT_VAL__
                
                writer.put(ThreatStore.__serializeKey(key),ThreatStore.__serializeValue(val))

    def delete(self,store,key):
        self.__dbpointers[store].delete(ThreatStore.__serializeKey(key))

    def keys(self,store):
        return self.__dbpointers[store].iterator(include_value=False)

    def keyslen(self,store):
        lens = set()
        for key in self.keys(store):
            lens.add(len(key))

        return lens

    def keyschecksum(self,store,baseencoded=False):
        keys = []
        for key in self.keys(store):
            keys.extend(key)

        hashdata = hashlib.sha256(b''.join(keys)).digest()
        if baseencoded:
            return base64.b64encode(hashdata)
        else:
            return hashdata

    def truncate(self,store):
        # Possible KABOOM
        logging.info("[LevelDB][%s] Truncating", store)
        self.__dbpointers[store].close()
        self.__truncatedb(store)
        self.__dbpointers[store] = self.__createdb(store)
