/*
 * Copyright 2013 Aaron Frase
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@SuppressWarnings("ResultOfMethodCallIgnored")
/**
 * Encrypts and decrypts data, also will create an EAS key
 * and encrypts it using a private key.
 */
public class CFCrypto
{
    private final Cipher pkCipher;
    private final Cipher aesCipher;
    private int AES_Key_Size = 128; // AES 256 requires the unlimited strength jurisdiction policy files
    private byte[] aesKey;
    private SecretKeySpec aeskeySpec;

    /**
     * Constructor class to setup the ciphers
     *
     * @throws GeneralSecurityException Usually thrown when we can't find the specific ciphers
     */
    public CFCrypto() throws GeneralSecurityException
    {
        // create RSA public key cipher
        pkCipher = Cipher.getInstance("RSA");
        // create AES shared key cipher
        aesCipher = Cipher.getInstance("AES");
    }

    /**
     * Creates an AES key based on AES_Key_Size int
     */
    private void makeKey() throws NoSuchAlgorithmException
    {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(AES_Key_Size);
        // Generate a random AES key
        SecretKey key = kgen.generateKey();
        aesKey = key.getEncoded();
        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
     * Creates, encrypts, and saves a symmetric key.
     *
     * @param symmetricKeyOut File object of where to save the encrypted symmetric key.
     * @param publicKeyFile   File object of the public key used to encrypt the symmetric key.
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void saveKey(File symmetricKeyOut, File publicKeyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException
    {
        // read public key to be used to encrypt the AES key
        byte[] encodedKey = new byte[(int) publicKeyFile.length()];
        new FileInputStream(publicKeyFile).read(encodedKey);

        // create public key
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pk = kf.generatePublic(publicKeySpec);

        makeKey();

        // write AES key
        pkCipher.init(Cipher.ENCRYPT_MODE, pk);
        CipherOutputStream os = new CipherOutputStream(new FileOutputStream(symmetricKeyOut), pkCipher);
        os.write(aesKey);
        os.close();
    }

    /**
     * Decrypts the symmetric key to be used for encryption/decryption.
     *
     * @param symmetricKeyFile The encrypted symmetric key.
     * @param privateKeyFile   The private key.
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     */
    public void loadKey(File symmetricKeyFile, File privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException
    {
        // read private key to be used to decrypt the AES key
        byte[] encodedKey = new byte[(int) privateKeyFile.length()];
        new FileInputStream(privateKeyFile).read(encodedKey);

        // create private key
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(privateKeySpec);

        // read AES key
        pkCipher.init(Cipher.DECRYPT_MODE, pk);
        aesKey = new byte[AES_Key_Size / 8];
        CipherInputStream is = new CipherInputStream(new FileInputStream(symmetricKeyFile), pkCipher);
        is.read(aesKey);

        aeskeySpec = new SecretKeySpec(aesKey, "AES");
    }

    /**
     * Encrypts data using the symmetric key
     *
     * @param data Data to be encrypted.
     * @return Encrypted data.
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] encrypt(byte[] data) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        aesCipher.init(Cipher.ENCRYPT_MODE, aeskeySpec);
        return aesCipher.doFinal(data);
    }

    /**
     * Decrypts an encrypted data
     *
     * @param encryptedData Data to be decrypted.
     * @return The decrypted data.
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public byte[] decrypt(byte[] encryptedData) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        aesCipher.init(Cipher.DECRYPT_MODE, aeskeySpec);
        return aesCipher.doFinal(encryptedData);
    }
}
