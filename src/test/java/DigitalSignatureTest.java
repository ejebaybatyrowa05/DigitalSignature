import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class DigitalSignatureTest {

    @TempDir
    Path tempDir;

    @Test
    void testGenerateKeyPair() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        assertNotNull(kp);
        assertEquals("RSA", kp.getPublic().getAlgorithm());
    }

    @Test
    void testPublicKeyPEMFormat() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String pem = DigitalSignature.toPEM("PUBLIC KEY", kp.getPublic().getEncoded());
        assertTrue(pem.startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(pem.trim().endsWith("-----END PUBLIC KEY-----"));
    }

    @Test
    void testPrivateKeyPEMFormat() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String pem = DigitalSignature.toPEM("PRIVATE KEY", kp.getPrivate().getEncoded());
        assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"));
        assertTrue(pem.trim().endsWith("-----END PRIVATE KEY-----"));
    }

    @Test
    void testSaveAndLoadPublicKey() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        Path pubFile = tempDir.resolve("public_key.pem");
        Files.writeString(pubFile, DigitalSignature.toPEM("PUBLIC KEY", kp.getPublic().getEncoded()));

        PublicKey loaded = DigitalSignature.loadPublicKey(pubFile);
        assertEquals(kp.getPublic(), loaded);
    }

    @Test
    void testSaveAndLoadPrivateKey() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        Path privFile = tempDir.resolve("private_key.pem");
        Files.writeString(privFile, DigitalSignature.toPEM("PRIVATE KEY", kp.getPrivate().getEncoded()));

        PrivateKey loaded = DigitalSignature.loadPrivateKey(privFile);
        assertEquals(kp.getPrivate(), loaded);
    }

    @Test
    void testValidSignature() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String doc = "Electronic document test";
        byte[] sig = DigitalSignature.signDocument(doc, kp.getPrivate());

        assertTrue(DigitalSignature.verifySignature(doc, sig, kp.getPublic()));
    }

    @Test
    void testModifiedDocumentFails() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String doc = "Original text";
        byte[] sig = DigitalSignature.signDocument(doc, kp.getPrivate());

        assertFalse(DigitalSignature.verifySignature("Modified text", sig, kp.getPublic()));
    }

    @Test
    void testWrongPublicKeyFails() throws Exception {
        KeyPair kp1 = DigitalSignature.generateKeyPair();
        KeyPair kp2 = DigitalSignature.generateKeyPair();
        String doc = "Secret document";
        byte[] sig = DigitalSignature.signDocument(doc, kp1.getPrivate());

        assertFalse(DigitalSignature.verifySignature(doc, sig, kp2.getPublic()));
    }

    @Test
    void testCorruptedSignatureFails() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String doc = "Integrity check";
        byte[] sig = DigitalSignature.signDocument(doc, kp.getPrivate());
        sig[0] ^= 0xFF;

        assertFalse(DigitalSignature.verifySignature(doc, sig, kp.getPublic()));
    }

    @Test
    void testEmptyDocumentSignature() throws Exception {
        KeyPair kp = DigitalSignature.generateKeyPair();
        String doc = "";
        byte[] sig = DigitalSignature.signDocument(doc, kp.getPrivate());

        assertTrue(DigitalSignature.verifySignature(doc, sig, kp.getPublic()));
    }
}
