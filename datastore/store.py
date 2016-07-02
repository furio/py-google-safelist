import unqlite

class ThreatStore(object):
    def __init__(self,dbpath,dbtypes):
        self.__dbpointers = {}
        for x in dbtypes:
            self.__dbpointers[x] = unqlite.UnQLite(dbpath + '/' + x + ".db")
      
            self.__dbrecordkeep = unqlite.UnQLite(dbpath + '/' + "master-rescord" + ".db")

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        for key in self.__dbpointers.keys():
            self.__dbpointers[key].close()

        self.__dbrecordkeep.close()

    def key(self,store,key):
        return self.__dbpointers[store][key]