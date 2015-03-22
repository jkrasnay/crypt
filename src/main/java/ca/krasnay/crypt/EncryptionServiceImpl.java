/* Copyright 2015 John Krasnay
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ca.krasnay.crypt;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionServiceImpl implements EncryptionService {

    private static final Charset UTF8 = Charset.forName("utf-8");

    private static final String ALGORITHM = "AES";

    private static final String CIPHER = "AES/CBC/PKCS5Padding";

    private static final int KEY_SIZE = 128;

    private Map<String, SecretKey> keyMap = new LinkedHashMap<String, SecretKey>();

    private SecretKey encKey;

    private String encKeyId;

    public EncryptionServiceImpl(List<String> keys) {

        for (String keyString : keys) {
            encKey = new SecretKeySpec(Base64.decode(keyString), ALGORITHM);
            encKeyId = getKeyId(encKey);
            keyMap.put(encKeyId, encKey);
        }

        // Note, at the end of this encKey and encKeyId is initialized to the
        // last provided key

    }

    @Override
    public byte[] decrypt(String cipherText) {

        try {

            if (!cipherText.startsWith("$")) {
                throw new RuntimeException("Malformed cipher text");
            }

            int index = cipherText.indexOf("$", 1);

            if (index < 0) {
                throw new RuntimeException("Malformed cipher text");
            }

            String keyId = cipherText.substring(1, index);
            SecretKey key = keyMap.get(keyId);

            if (key == null) {
                throw new RuntimeException("Key with id " + keyId + " not found");
            }

            byte[] fullBlock = Base64.decode(cipherText.substring(index + 1));

            Cipher decryptCipher = Cipher.getInstance(CIPHER);
            int ivSize = decryptCipher.getBlockSize();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(fullBlock, 0, ivSize);
            decryptCipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

            return decryptCipher.doFinal(fullBlock, ivSize, fullBlock.length - ivSize);

        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }


    @Override
    public String decryptString(String cipherText) {
        return new String(decrypt(cipherText), UTF8);
    }

    @Override
    public String encrypt(byte[] plainText) {

        try {

            Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, encKey);

            byte[] iv = encryptCipher.getIV();

            byte[] encryptedBytes = encryptCipher.doFinal(plainText);

            byte[] fullBlock = new byte[iv.length + encryptedBytes.length];
            System.arraycopy(iv, 0, fullBlock, 0, iv.length);
            System.arraycopy(encryptedBytes, 0, fullBlock, iv.length, encryptedBytes.length);

            return "$" + encKeyId + "$" + Base64.encodeToString(fullBlock, false);

        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public String encryptString(String plainText) {
        return encrypt(plainText.getBytes(UTF8));
    }


    public String generateKey() {

        try {

            KeyGenerator kgen = KeyGenerator.getInstance(ALGORITHM);
            kgen.init(KEY_SIZE);
            SecretKey key = kgen.generateKey();
            return Base64.encodeToString(key.getEncoded(), false);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate the unique identifier for the given key.
     */
    private String getKeyId(SecretKey key) {
        try {

            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(key.getEncoded());
            byte[] digest = md.digest();
            return String.format("%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3]);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
