import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Cryptography {

    private static final int BLOCK_SIZE = 16;

    private static SecretKey getSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] getIV(byte[] fileData) {
        byte[] IV = new byte[BLOCK_SIZE];
        System.arraycopy(fileData, fileData.length - IV.length, IV, 0, IV.length);
        return IV;
    }

    private static byte[] xor(byte[] fileData, byte[] previous) {
        if (fileData.length == previous.length)
            for (int i = 0; i < fileData.length; i++)
                fileData[i] = (byte) (0xff & ((int) fileData[i]) ^ ((int) previous[i]));
        return fileData;
    }

    private static byte[] removePadding(byte[] fileData) {
        int paddingValue = fileData[fileData.length - 1];
        for (int i = fileData.length - paddingValue; i < fileData.length; i++)
            if (fileData[i] != paddingValue)
                return fileData;

        byte[] newFileData = new byte[fileData.length - paddingValue];
        System.arraycopy(fileData, 0, newFileData, 0, newFileData.length);
        return newFileData;
    }

    private static byte[] decrypt(byte[] fileData, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] newFileData = new byte[fileData.length - BLOCK_SIZE];

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(hexStringToByteArray(key)));

        byte[] IV = getIV(fileData);
        System.arraycopy(fileData, 0, newFileData, 0, newFileData.length);

        byte[] tampon = new byte[BLOCK_SIZE];
        byte[][] tempData = new byte[2][BLOCK_SIZE];
        for (int i = 0; i < newFileData.length; i += BLOCK_SIZE) {
            System.arraycopy(newFileData, i, tempData[0], 0, tempData[0].length);
            System.arraycopy(newFileData, i, tampon, 0, tampon.length);
            if (i == 0)
                System.arraycopy(xor(cipher.doFinal(tempData[0]), IV), 0, newFileData, i, tempData[0].length);
            else
                System.arraycopy(xor(cipher.doFinal(tempData[0]), tempData[1]), 0, newFileData, i, tempData[0].length);
            System.arraycopy(tampon, 0, tempData[1], 0, tempData[1].length);
        }
        return removePadding(newFileData);
    }

    public static byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        byte[] data = new byte[length/2];
        for (int i = 0; i < length; i += 2)
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), BLOCK_SIZE) << 4) + Character.digit(hex.charAt(i+1), BLOCK_SIZE));
        return data;
    }

    public static void main(String[] args) {
        System.out.println("Hello world!");
    }
}
