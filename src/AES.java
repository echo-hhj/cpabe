import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class AES {
    public static File encryptFile(File file, byte[] symmetricKey) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        FileOutputStream fos = new FileOutputStream("File/encrypted_" + file.getName());

        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(new byte[16]));

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) fos.write(output);
        }
        byte[] output = cipher.doFinal();
        if (output != null) fos.write(output);

        fos.flush();
        fos.close();
        fis.close();

        return new File("File/encrypted_" + file.getName());
    }

    public static File decryptFile(File file, byte[] symmetricKey) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        FileOutputStream fos = new FileOutputStream("File/" + file.getName().replace("encrypted", "decrypted"));

        SecretKeySpec keySpec = new SecretKeySpec(symmetricKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new byte[16]));

        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) fos.write(output);
        }
        byte[] output = cipher.doFinal();
        if (output != null) fos.write(output);

        fos.flush();
        fos.close();
        fis.close();

        return new File("File/decrypted_" + file.getName() );
    }
}
