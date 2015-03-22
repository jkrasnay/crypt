# crypt

Crypt is a simple encryption library for Java that focuses on encrypting relatively short strings for storing in a database.

The central crypt component is the `EncryptionService`, which is configured with one or more keys stored in a configuration file on the application server. Data is encrypted using AES 128-bit encryption, then encoded to a string using Base64.

## Key Rotation

Key rotation is supported by configuring the encryption service with multiple keys. Each encrypted field is prefixed with a hash that indicates the key with which it was encrypted, so that you can add new keys without having to re-encrypt all your data. Data is always encrypted with the last configured key. Key rotation can therefore be performed as follows:

- generate a new key and add it to the encryption service configuration
- write code to read and re-encrypt each encrypted field on a schedule that makes sense for your application

## Key Generation

Crypt comes with a command-line utility to generate new keys:

    java -jar crypt.jar ca.krasnay.crypt.GenerateKey


