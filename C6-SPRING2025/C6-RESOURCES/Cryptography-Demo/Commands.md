# 🛡️ Cybersecurity Hands-On Demos

Welcome to the **Cybersecurity Hands-On Demos** repository! This guide provides step-by-step **hashing and encryption** exercises using OpenSSL and Linux commands. These are practical demonstrations of cryptographic concepts used in cybersecurity.

---

## 🔹 Hashing: MD5 & SHA-256
Hashing transforms data into a **fixed-length string**, ensuring data integrity.

### **MD5 Hashing**
MD5 produces a **128-bit hash** but is **not cryptographically secure** due to vulnerabilities.
#### **💻 Try it out:**
```bash
echo -n "Hello, World!" | md5sum
Concept	Command	Purpose
AES Encryption	openssl enc -aes-256-cbc -salt -in file.txt -out encrypted.txt -k password	Encrypts data using AES
AES Decryption	openssl enc -aes-256-cbc -d -in encrypted.txt -k password	Decrypts AES-encrypted data
Generate RSA Keys	openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048	Generates an RSA private key
Extract RSA Public Key	openssl rsa -pubout -in private_key.pem -out public_key.pem	Extracts public key from private key
Encrypt Message with RSA	openssl rsautl -encrypt -pubin -inkey public_key.pem -in message.txt -out encrypted_message.bin	Encrypts a message using the public key
Decrypt Message with RSA	openssl rsautl -decrypt -inkey private_key.pem -in encrypted_message.bin	Decrypts message with private key
Hash String with SHA-256	`echo -n "mypassword"	sha256sum`
Hash File with SHA-256	sha256sum myfile.txt	Computes file integrity hash
Hash String with MD5	`echo -n "mypassword"	md5sum`
