# simpleFernet
A simple Fernet encryption & decryption library using Python's Cryptography library.

## Usage
```python
import simple_fernet as fernet

password = 'p@ssw0rd'
text = 'Secret Text :D'

# encrypt text
encrypted_text = fernet.encrypt(text, password)
print(encrypted_text)

# decrypt text
decrypted_text = fernet.decrypt(encrypted_text, password)
print(decrypted_text)
```
