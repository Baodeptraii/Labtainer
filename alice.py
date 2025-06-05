from server import Server
# from faker import Faker

class Alice:
    def __init__(self) -> None:
        '''
        
        # Uncomment the below lines to use a custom message and key
        fake = Faker()
        words = fake.text().split(" ")[:5]
        self._msg = " ".join(word for word in words)
        words = fake.text().split(" ")[:3]
        self._key = " ".join(word for word in words)
        
        '''
        # Your message and key are here
        with open("alice_message.txt", "r", encoding="utf-8") as f:
            lines = f.read().strip().splitlines()
            if len(lines) < 2:
                raise ValueError("File alice_message.txt must contain at least two lines: <msg> and <key>")
            self._msg = lines[0]
            self._key = lines[1]


        self.msgLength = len(self._msg)
        self._encServer = Server(self._key)
     
            
        self._requestEncryption()
        
    def __str__(self) -> str:
        return "I am Alice. I use an Encryption server to encrypt my messages. I don't know why. but I feel like someone is always watching me 😓"
        
    def _requestEncryption(self):
        # print("plaintext :", self._msg)
        
        print("ciphertext:", (self._encServer.httpRequestForEncryptedText(self._msg)).hex())
    
    def forceRequestandIntercept(self, prefix, pos=-1, iv = 0):
        """Function to force Alice to make a request to the server, and help perform MITM to get the ciphertext that the server returned.

        Args:
            prefix (str, bytes): the prefix to the message that Alice will send to the server
            pos (int, optional): The message byte of this position will be added after the prefix. If blank, then nothing will be added to the prefix.
            iv (bytes, optional): IV (Initial Vector) to send to use to do the encryption. Can be omitted (in that case random IV will be used)

        Returns:
            bytes: ciphertext, that you received by MITM
        """
        if isinstance(prefix, str):
            prefix = prefix.encode('utf-8')
        # if pos != 1, then add the secret message's pos byte after the prefix
        if pos != -1:
            prefix = prefix + self._msg[pos].encode()
        
        # return the ciphertext for the plaintext we sent
        return self._encServer.httpRequestForEncryptedText(prefix, iv)
        

alice = Alice()
print(alice)
        
    
    