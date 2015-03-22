package ca.krasnay.crypt;


/**
 * Encryption service, used to encrypt data stored in the database. The service
 * must be initialized with one or more keys, each with a separate numeric ID.
 * The keys should come from a different storage location than the data being
 * encrypted. Typically, the keys are configured in a configuration properties
 * file and the encrypted data is in the database.
 *
 * <p>The service generates ciphertext as a string consisting of the following
 * elements:
 *
 * <ul>
 * <li>The ID of the key used to encrypt the data
 * <li>A colon
 * <li>A base64-encoded byte array consisting of the initialization vector
 * followed by the encrypted data
 * </ul>
 *
 * <p>The scheme of maintaining several keys and storing the key ID with the
 * ciphertext is meant to facilitate key rotation. Data is always encrypted with
 * the latest key, while data encrypted with a previous key can still be decrypted
 * so long as the key is still configured. To rotate a key, an new key would be
 * generated and appended to the configuration. Then, some application-specific
 * routine would be expected to visit and re-encrypt all existing data. If
 * this routine fails before completion, the system will still be able to
 * function until the update routine can be fixed.
 *
 * @author <a href="mailto:john@krasnay.ca">John Krasnay</a>
 */
public interface EncryptionService {

    /**
     * Decrypts the given cipher text to a byte array.
     */
    public byte[] decrypt(String cipherText);

    /**
     * Decrypts the given cipher text as a UTF-8 encoded
     * string.
     */
    public String decryptString(String cipherText);

    /**
     * Encrypts a byte array.
     */
    public String encrypt(byte[] plainText);

    /**
     * Encrypts the UTF-8 encoded bytes of the given string.
     */
    public String encryptString(String plainText);

    /**
     * Generates a new key for this service.
     */
    public String generateKey();

}
