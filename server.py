from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class Server:
    def __init__(self, key):
        # creating the key using MD5 (key is private)
        self._key_bytes = md5(key.encode('utf-8')).digest()
        
    def __str__(self):
        return "AES Encryption Server, uses CBC mode ⚙️"
    
    def _aes_encrypt(self, data, iv=0):
        if isinstance(data, str):
            data = data.encode('utf8')
        
        # so that we can supply iv on our own
        if(iv == 0):
            iv = get_random_bytes(AES.block_size)

        # Using CBC mode to perform BEAST attack
        cipher = AES.new(self._key_bytes, AES.MODE_CBC, iv)
        
        # Using GCM mode for encryption
        # cipher = AES.new(self._key_bytes, AES.MODE_GCM, iv)
        
        ciphertext = iv + cipher.encrypt(pad(data, AES.block_size))

        return ciphertext
    
    def _aes_decrypt(self, data):
        iv = data[:AES.block_size]
        cipher = AES.new(self._key_bytes, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
        
        return decrypted_data.decode('utf-8')
    
    def httpRequestForEncryptedText(self, plaintext, iv=0):
        """This function returns encrypted text for the supplied plaintext using AES algorithm. The key is supposed to be the shared session key, that only the server knows, and is private info. The IV is configurable, but if not supplied, a random IV is used.

        Args:
            plaintext (string/byte): String/byte to be encrypted
            iv (bytes, optional): IV (Initial Vector) to use. if omitted, a random IV is used.

        Returns:
            _type_: _description_
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf8')
        
        return self._aes_encrypt(plaintext, iv)

server = Server("test_key_for_initialization")
print(server)