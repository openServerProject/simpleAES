# simpleAES
A simple AES encryption & decryption library using Python's Cryptography library.  
It supports AES-CTR for compatibility with JavaScript.

## Usage
```python
import simple_aes as aes

password = 'p@ssw0rd'
text = 'Secret Text :D'

# encrypt text
encrypted_text = aes.encrypt(text, password)
print(encrypted_text)

# decrypt text
decrypted_text = aes.decrypt(encrypted_text, password)
print(decrypted_text)
```
