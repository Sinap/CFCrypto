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

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

/**
 * A wrapper to make it easier to use CFCrypto from ColdFusion pages.
 */
public class CFCryptoWrapper
{
    private static CFCrypto cfCrypto;
    private static BASE64Encoder base64Encoder;
    private static BASE64Decoder base64Decoder;

    /**
     * Constructor
     *
     * @param symmetricKeyFilePath The path to the encrypted symmetric key.
     * @param privateKeyFilePath   The path to the private key.
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public CFCryptoWrapper(String symmetricKeyFilePath, String privateKeyFilePath) throws GeneralSecurityException, IOException
    {
        cfCrypto = new CFCrypto();
        base64Encoder = new BASE64Encoder();
        base64Decoder = new BASE64Decoder();

        File symmetricKeyFile = new File(symmetricKeyFilePath);
        File privateKeyFile = new File(privateKeyFilePath);
        cfCrypto.loadKey(symmetricKeyFile, privateKeyFile);
    }

    /**
     * Encrypts a string
     *
     * @param plainText The string to encrypt
     * @return Encrypted encoded string
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    public String encrypt(String plainText) throws BadPaddingException, InvalidKeyException, IllegalBlockSizeException
    {
        return base64Encoder.encode(cfCrypto.encrypt(plainText.getBytes()));
    }

    /**
     * Decrypts a string
     *
     * @param encryptedString the encrypted string
     * @return Decrypted plain text.
     * @throws IOException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     */
    public String decrypt(String encryptedString) throws IOException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException
    {
        return new String(cfCrypto.decrypt(base64Decoder.decodeBuffer(encryptedString)));
    }
}