import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class DigitalSignature {

    private static final String ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) {

        try (Scanner scanner = new Scanner(System.in)) {

            System.out.println("======================================");
            System.out.println("     ELECTRONIC SIGNATURE SYSTEM");
            System.out.println("======================================");
            System.out.println("Student: Ejebay Batyrova");

            // 1. RSA-2048 кілттерін жасау
            KeyPair keyPair = generateKeyPair();
            System.out.println("\n[1] RSA-2048 keys generated!");

            // 2. PEM форматында кілттерді дайындау
            String publicKeyPEM = toPEM("PUBLIC KEY", keyPair.getPublic().getEncoded());
            String privateKeyPEM = toPEM("PRIVATE KEY", keyPair.getPrivate().getEncoded());

            // 3. Кілттерді сақтау
            Path pubPath = Path.of("public_key.pem");
            Path privPath = Path.of("private_key.pem");
            Files.writeString(pubPath, publicKeyPEM);
            Files.writeString(privPath, privateKeyPEM);

            System.out.println("[2] Public key saved!");
            System.out.println("[3] Private key saved!");

            // 4. Құжат мәтінін енгізу
            System.out.print("\nEnter document text: ");
            String document = scanner.nextLine();

            if (document.isBlank()) {
                document = "Electronic document. Student: Ejebay Batyrova.";
            }

            Files.writeString(Path.of("document.txt"), document);
            System.out.println("[4] Document saved!");

            // 5. PEM файлдарынан кілттерді оқып, қолтаңба жасау
            PrivateKey loadedPrivateKey = loadPrivateKey(privPath);
            byte[] signedBytes = signDocument(document, loadedPrivateKey);

            String signedText = Base64.getEncoder().encodeToString(signedBytes);
            Files.writeString(Path.of("signature.sig"), signedText);

            System.out.println("[5] Digital signature created!");
            System.out.println("Algorithm: " + ALGORITHM);

            // 6. PEM файлынан ашық кілтті оқып, қолтаңбаны тексеру
            PublicKey loadedPublicKey = loadPublicKey(pubPath);
            boolean verification = verifySignature(document, signedBytes, loadedPublicKey);

            System.out.println("\n======================================");
            System.out.println("          VERIFICATION RESULT");
            System.out.println("======================================");
            System.out.println("Signature valid: " + verification);

            // 7. Өзгертілген құжатты тексеру
            String changedDocument = document + " CHANGED";
            boolean changedVerification = verifySignature(changedDocument, signedBytes, loadedPublicKey);

            System.out.println("Modified document valid: " + changedVerification);

            System.out.println("\n======================================");
            System.out.println("             SYSTEM COMPLETED");
            System.out.println("======================================");
            System.out.println("Student: Ejebay Batyrova");

            System.out.println("\nGenerated files:");
            System.out.println("1. public_key.pem");
            System.out.println("2. private_key.pem");
            System.out.println("3. document.txt");
            System.out.println("4. signature.sig");

        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // RSA-2048 кілт жұбын жасау
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    // PEM форматын жасау
    public static String toPEM(String type, byte[] data) {
        String encoded = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(data);
        return "-----BEGIN " + type + "-----\n" + encoded + "\n-----END " + type + "-----\n";
    }

    // PEM файлынан PublicKey оқу
    public static PublicKey loadPublicKey(Path path) throws Exception {
        String pem = Files.readString(path)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }

    // PEM файлынан PrivateKey оқу
    public static PrivateKey loadPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(pem);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    // Құжатқа қол қою
    public static byte[] signDocument(String document, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(privateKey);
        signature.update(document.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }

    // Электрондық қолтаңбаны тексеру
    public static boolean verifySignature(String document, byte[] signedBytes, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(publicKey);
        verifier.update(document.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signedBytes);
    }
}
