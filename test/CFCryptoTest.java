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

import static org.junit.Assert.*;

public class CFCryptoTest
{
    private static final String testString = "wpWda/IF;Vj1<3s#.=?esoFU&?!}jH}\\t)ZQ{VD0z*f4huF=~\"F4:cS:+j+TW:z";
    private static CFCrypto cfCrypto;
    private static File encryptedKeyFile;
    private static File publicKeyFile;
    private static File privateKeyFile;
    private static byte[] encryptedTestString;

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        cfCrypto = new CFCrypto();
        publicKeyFile = new File("test/publickey.der");
        privateKeyFile = new File("test/private.der");

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
    public void testSaveKey() throws Exception
    {
        encryptedKeyFile = new File("test/encryptedKey");
        cfCrypto.saveKey(encryptedKeyFile, publicKeyFile);
        assertTrue(encryptedKeyFile.isFile());
    }

    @Test
    public void testLoadKey() throws Exception
    {
        cfCrypto.loadKey(encryptedKeyFile, privateKeyFile);
        assertNotNull(cfCrypto);
    }

    @Test
    public void testEncrypt() throws Exception
    {
        encryptedTestString = cfCrypto.encrypt(testString.getBytes());
        // can't think of a good test
        assertNotSame(testString, encryptedTestString);
    }

    @Test
    public void testDecrypt() throws Exception
    {
        byte[] decryptedTestString = cfCrypto.decrypt(encryptedTestString);
        assertEquals(testString, new String(decryptedTestString));
    }
}
