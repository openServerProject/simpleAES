# simpleAES
Simple AES encryption & decryption library for JavaScript and Python.

## Important
The JavaScript version of this library uses the minified version of `crypto-js`, is why the JavaScript version is very large compared to the Python version.

## Usage
### Python 3
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
### JavaScript
Script tag: `<script src=""></script>`
```javascript
const password = 'p@ssw0rd';
const text = 'Secret Text :D';

// encrypt text
const encrypted_text = encrypt(text, password);
console.log(encrypted_text);

// decrypt text
const decrypted_text = decrypt(encrypted_text, password);
console.log(decrypted_text);
```
