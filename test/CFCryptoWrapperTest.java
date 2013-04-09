import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class CFCryptoWrapperTest
{
    private static final String testString = "wpWda/IF;Vj1<3s#.=?esoFU&?!}jH}\\t)ZQ{VD0z*f4huF=~\"F4:cS:+j+TW:z";
    private static CFCryptoWrapper cfCryptoWrapper;
    private static File encryptedKeyFile;
    private static File publicKeyFile;
    private static File privateKeyFile;
    private static String encryptedString;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        publicKeyFile = new File("test/publickey.der");
        privateKeyFile = new File("test/private.der");
        encryptedKeyFile = new File("test/encryptedKey");

        // generate the key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        PrivateKey privateKey = keyGen.genKeyPair().getPrivate();
        PublicKey publicKey = keyGen.genKeyPair().getPublic();

        // write public key to file
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(publicKeyFile);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.close();

        // write private key to file
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        fos = new FileOutputStream(privateKeyFile);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.close();

        assertTrue(publicKeyFile.exists());
        assertTrue(privateKeyFile.exists());

        CFCrypto cfCrypto = new CFCrypto();
        cfCrypto.saveKey(encryptedKeyFile, publicKeyFile);
        cfCryptoWrapper = new CFCryptoWrapper(encryptedKeyFile.getPath(), privateKeyFile.getPath());
    }

    @AfterClass
    public static void tearDownClass() throws Exception
    {
        System.gc(); // quick and dirty workaround to get java to release the file lock
        Thread.sleep(10); // gc sometimes isn't quick enough

        assertTrue(publicKeyFile.delete());
        assertTrue(privateKeyFile.delete());
        assertTrue(encryptedKeyFile.delete());
    }

    @Test
    public void testEncrypt() throws Exception
    {
        encryptedString = cfCryptoWrapper.encrypt(testString);
    }

    @Test
    public void testDecrypt() throws Exception
    {
        String decryptedString = cfCryptoWrapper.decrypt(encryptedString);
        assertEquals(testString, decryptedString);
    }
}
