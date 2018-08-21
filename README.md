### About jeeq
**jeeq is an encrypting tool using ECDSA.**

**ECDSA** (Elliptic Curve Digital Signature Algoritm) is not designed for encryption but signing, but by tricking it one can make it encrypt anything.
Please note it's not a code you can rely on. Don't even think about implementing that into a working project.


#### @Rutrus's Version

This version is intended to be used a proof of concept of Elliptic Curve.
The original code was discused on [BitcoinTalk.org](https://bitcointalk.org/index.php?topic=196378.0)


Python3 will be required.

### How to use it

```
#ENCRYPTION (-e)
python jeeq.py -e                                                 #Will ask for the text to encrypt, the recipient's public key and will print the output
python jeeq.py -e -i secretkeys.txt                               #Will ask the recipient's public key, will encrypt secretkeys.txt and will print the output
python jeeq.py -e -i secretkeys.txt -o encryptedsk                #Will ask the recipient's public key, will encrypt secretkeys.txt and will write the output to the file encryptedsk
python jeeq.py -e -k 0499a6037487a0ea0ae4867f7e60a6c4ac477103b4d3ed9ce8c84804a32f53ff802633de6e8ccd6a9b13fab97a29b0bda794576613f5abc17b40d993629c457aae
               #Will ask for the text to encrypt, will use the given recipient's public key and will print the output

#DECRYPTION (-d)
python jeeq.py -d                                                 #Will ask for the text to decrypt, the recipient's private key and will print the output
python jeeq.py -d -i encryptedsk                                  #Will ask the recipient's private key, will decrypt encryptedsk and will print the output
python jeeq.py -d -i encryptedsk -o secretkeys-decrypted.txt      #Will ask the recipient's private key, will decrypt encryptedsk and will write the output to the file secretkeys-decrypted.txt
python jeeq.py -d -k 0000000000000000000000000000000000000000000000000000000000000001
               #Will ask for the text to decrypt, will use the given recipient's private key and will print the output
```