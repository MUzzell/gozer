import pdb
from pyme import core, pygpgme

class PgpKeyError(BaseException):
    
    def __init__(self, message = ''):
        self.message = message

class KeyManager():

    def __init__(self):
        self.context = core.Context()
        self.context.set_armor(1)

    
    def export_keyring(self):
        cypher = core.Data()
        
        result = self.context.op_export('', 0, cypher)
        cypher.seek(0,0)
        return cypher.read()

    def get(self, key_id):
        cypher = core.Data()
        result = self.context.op_export(key_id,0, cypher)
        if result is None:
            cypher.seek(0,0)
            return cypher.read()
        else:
            raise PgpKeyError("Could not find key")

    def search(self, search, get_sigs = False):
        if get_sigs:
            self.context.set_keylist_mode(pygpgme.GPGME_KEYLIST_MODE_SIG_NOTATIONS | pygpgme.GPGME_KEYLIST_MODE_SIGS)
        self.context.op_keylist_start(search, 0 )
        keys = []
        while True:
            key = self.context.op_keylist_next()
            if key is None:
                break
            keys.append(PGPKey(key))
        return keys
    
    def add(self, key):
        cypher = core.Data()
        cypher.new_from_mem(key)
        self.context.op_import(cypher)
        result = self.context.op_import_result()
        if result is not None and result.imports is not None and len(result.imports) > 0:
            return len([x for x in result.imports if x.status == 0])   
        raise PgpKeyError("Error storing key")

class PGPKey():
    
    def __init__(self, key):
        self.uids = key.uids
        self.pub_key = key.subkeys[0] #the first key is the public key
        self.sub_keys = key.subkeys[1:]
    def build_flags(self, obj):
        result = ''
        result += 'r' if hasattr(obj, 'revoked') and self.pub_key.revoked != 0 else ''
        result += 'd' if hasattr(obj, 'disabled') and self.pub_key.disabled != 0 else ''
        result += 'e' if hasattr(obj, 'expired') and self.pub_key.expired != 0 else ''
        return result

    def __str__(self):
        result = ''
        result += 'pub:%s:%d:%d:%s:%s:%s\n' % (
            self.pub_key.keyid[8:], 
            self.pub_key.length,
            self.pub_key.pubkey_algo,     
            self.pub_key.timestamp if self.pub_key.timestamp is not 0 else '',
            self.pub_key.expired if self.pub_key.timestamp is not 0 else '',
            self.build_flags(self.pub_key))
        for uid in self.uids:
            result += 'uid:%s:%d::%s\n' % (
                str(uid.uid),
                self.pub_key.timestamp,
                self.build_flags(uid))
        return result
