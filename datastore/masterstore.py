class KeeperStore(object):
    @staticmethod
    def getPrefixes(store, threat):
        return store.get('KEEPER',threat + ':prefixlen')

    @staticmethod
    def setPrefixes(store, threat, value):
        store.set('KEEPER',threat + ':prefixlen', value)

    @staticmethod
    def delPrefixes(store, threat):
        store.delete('KEEPER',threat + ':prefixlen')

    @staticmethod
    def getLastClistate(store, threat):
        return store.get('KEEPER',threat + ':lastclistate')

    @staticmethod
    def hasLastClistate(store, threat):
        return store.exist('KEEPER',threat + ':lastclistate')

    @staticmethod
    def setLastClistate(store, threat, value):
        store.set('KEEPER',threat + ':lastclistate', value)

    @staticmethod
    def delLastClistate(store, threat):
        store.delete('KEEPER',threat + ':lastclistate')

    @staticmethod
    def getChecksum(store, threat):
        return store.get('KEEPER',threat + ':checksum')

    @staticmethod
    def setChecksum(store, threat, value):
        store.set('KEEPER',threat + ':checksum', value)

    @staticmethod
    def delChecksum(store, threat):
        store.delete('KEEPER',threat + ':checksum')

    @staticmethod
    def truncate(store, threat):
        KeeperStore.delPrefixes(store,threat)
        KeeperStore.delLastClistate(store,threat)
        KeeperStore.delChecksum(store,threat)