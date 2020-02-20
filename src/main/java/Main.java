import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        byte[] fileData = new byte[15];
        for(int i = 0; i < fileData.length; i++)
            fileData[i] = (byte) i;

        System.out.println(Arrays.toString(fileData));
        System.out.println(fileData.length);

        byte[] eFileData = Cryptography.encrypt(fileData, "666666666666666666666666666666666666666666666666");

        System.out.println(Arrays.toString(eFileData));
        System.out.println(eFileData.length);

        byte[] dFileData = Cryptography.decrypt(eFileData, "666666666666666666666666666666666666666666666666");

        System.out.println(Arrays.toString(dFileData));
        System.out.println(dFileData.length);

        System.out.println(Arrays.toString(args));
        System.out.println(Arguments.getEncryptionType(args));
        System.out.println(Arguments.getKey(args));
        System.out.println(Arguments.getInputFile(args));
        System.out.println(Arguments.getOutputFile(args));
    }
}
