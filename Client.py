import os
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import binascii
import base64
import hmac, hashlib
import pickle
import collections
_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}

class Client:
    def __init__(self):
        self.iv = os.urandom(16)
        self.keyword_sk = os.urandom(32) #generate a Pseudo-random number as secret key for keywords
        self.doc_sk = os.urandom(32) #generate a Pseudo-random number as secret key for documents
        #self.content = content #content of the document
        self.encrypted_index = {}
        self.search_history = {}
    def initIndex(self, index):
        self.index = index   
    #pad to mod 32
    def add_to_32(self, text):
        if(type(text) is not bytes):
            text.encode('utf-8')
        if len(text) % 32:
            add = 32 - (len(text) % 32)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')
    
    #hash keyword
    def encrypt_keyword(self, key, keyword):
        encrypted_keyword = hmac.new(key, keyword, hashlib.sha256).digest()
        return encrypted_keyword

    #encrypt documents and add encrypted keyword and encrypted documents to the encrypted index
    def encrypt(self, keyword, doc_content):
        #self.encrypted_index.clear()
        
        #encrypt the keyword
        encrypted_keyword = self.encrypt_keyword(self.keyword_sk, bytes(keyword,'utf-8'))
        encrypted_keyword = encrypted_keyword.decode()
        #encrypt the document
        enc_content = self.aesEncrypt(self.doc_sk, doc_content, self.iv)
        
        self.encrypted_index[encrypted_keyword] = enc_content
        return self.encrypted_index[encrypted_keyword]

    #generate index of encrypted keywords 
    def initKeyword(self, filename):
        with open('keys', "rb") as f:
            keys = pickle.load(f)
        keywords= collections.OrderedDict()
        encrypted_index = collections.OrderedDict()
        #encrypted_keyword_list = []
        keyword_sk = keys[0]
        iv = keys[2]
        with open(filename, "r") as f:
            line = f.readlines()
            for tmp in line:
                tmp = tmp.rstrip("\n")
                #keywords[values[0]] = {str(x) for x in values[1:len(values)]}
                keywords[tmp.split(" ")[0]] = tmp.split(" ")[1:]
        for indentifier in keywords:
            #the first key of the index is to store encrypted indentifier
            encrypted_indentifier = self.encrypt_keyword(keyword_sk, bytes(indentifier,'utf-8'))
            encrypted_index[encrypted_indentifier] = ''
            keyword = keywords[indentifier]
            for k in keyword:
                #encrypted_keyword = self.string2HashedBinary(k)
                encrypted_keyword = self.aesEncrypt(keyword_sk, k, iv)
                #encrypted_keyword_list.append(encrypted_keyword)
                iv = self.keytrim(encrypted_keyword)
                encrypted_index[encrypted_keyword] = ''
            self.encrypted_index = encrypted_index
            #print(encrypted_index)
        return encrypted_index

    def search(self, search_keyword):
        encrypted_index= collections.OrderedDict()
        search_history = {}
        with open('encrypted_index', "rb") as f:
            encrypted_index = pickle.load(f)
        with open('keys', "rb") as f:
            keys = pickle.load(f)
        with open('search_history', "rb") as f:
            search_history = pickle.load(f)
        #print(keys)
        #print(encrypted_index)
        keyword_sk = keys[0]
        iv = keys[2]
        count = 0
        isFound = 0 
        hasSearched = 0
        enc_search_keyword = self.encrypt_keyword(keyword_sk, bytes(search_keyword,'utf-8'))
        #if the keyword is already searched before, read the search history from file
        if(enc_search_keyword in search_history):
            isFound = 1
            count = search_history[enc_search_keyword]
            hasSearched = 1

        #else if the keyword is not searched before, search from the index
        if(hasSearched == 0):
            encrypted_keyword_list = list(encrypted_index.keys())
            encrypted_keyword_list.reverse()
            for index in range(1,len(encrypted_keyword_list)-1):
                keyword = self.aesDecrypt(keyword_sk, encrypted_keyword_list[index-1], self.keytrim(encrypted_keyword_list[index]))
                if(search_keyword == keyword ):
                    #print(len(encrypted_index[enc_keyword]))
                    if(len(encrypted_index[encrypted_keyword_list[index-1]]) != 0):
                        count += 1
                    isFound = 1
            keyword = self.aesDecrypt(keyword_sk, encrypted_keyword_list[len(encrypted_keyword_list)-2], iv)
            if(search_keyword == keyword):
                isFound = 1
                if(len(encrypted_index[encrypted_keyword_list[len(encrypted_keyword_list)-2]]) != 0):
                    count += 1
            search_history[enc_search_keyword] = count
            self.search_history = search_history

        if(isFound == 1):
            print("Keyword is found")
            print("the number of documents is %d" %count)
        else:
            print("Keyword is not found")

        
    def update(self, update_keyword, update_file_name=''):
        encrypted_index= collections.OrderedDict()
        search_history = {}
        with open('encrypted_index', "rb") as f:
            encrypted_index = pickle.load(f)
        with open('keys', "rb") as f:
            keys = pickle.load(f)
        with open('search_history', "rb") as f:
            search_history = pickle.load(f)
        #print(keys)
        #print(encrypted_index)
        keyword_sk = keys[0]
        doc_sk = keys[1]
        iv = keys[2]
        last_keyword = list(encrypted_index.keys())[-1]
        count = 0
        hash_keyword = self.encrypt_keyword(keyword_sk, bytes(update_keyword,'utf-8'))

        encrypted_keyword = self.aesEncrypt(keyword_sk, update_keyword, self.keytrim(last_keyword))
        if(update_file_name != ''):
            isFileExists = os.path.isfile(update_file_name)
            if(isFileExists):
                with open(update_file_name, "r") as f:
                    text = f.read()
                encrypted_doc = self.aesEncrypt(doc_sk, text, iv)
                count += 1
            else:
                print('the file does not exist')
                return
        else:
            encrypted_doc = ''
        if(hash_keyword in search_history):
            search_history[hash_keyword] += count
        else:
            search_history[hash_keyword] = count
        encrypted_index[encrypted_keyword] = encrypted_doc
        self.encrypted_index = encrypted_index
        self.search_history = search_history
        return encrypted_index

    #use aes to encrypt the document
    def aesEncrypt(self, key, text, iv):
        text = self.add_to_32(text)
        cryptos = AES.new(key, AES.MODE_CBC, iv)
        encrypted_text = cryptos.encrypt(text)
        #print(cipher_text)
        return encrypted_text

    def aesDecrypt(self, key, enc_text, iv):
        cryptos = AES.new(key, AES.MODE_CBC, iv)
        text = cryptos.decrypt(enc_text)
        return bytes.decode(text).rstrip('\0')

    def keytrim(self, key):
        if len(key) >= 16:
            return key[:16]

    #store encrypted index in a document
    def dump_encrypted_index(self):
        with open('encrypted_index', "wb") as file:
            file.write(pickle.dumps(self.encrypted_index))
        file.close()

    #store Keys in a document
    def dumpKeys(self):
        data =  (self.keyword_sk, self.doc_sk,self.iv)
        with open('keys', "wb") as file:
            file.write(pickle.dumps(data))
        file.close()

    #store search history in a document
    def dump_search_history(self):
        with open('search_history', "wb") as file:
            file.write(pickle.dumps(self.search_history))
        file.close()

