import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.security.SecureRandom;

public class Cryptography {
	
	private static SecretKeySpec secretKey;
    private static byte[] key  = {(byte)0xB2,(byte)0x0A,(byte)0xDE,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11};
    private static final int BLOC_SIZE_OCT = 16;
    
	public Cryptography() {
		
	}

    private static final int BLOCK_SIZE = 16;

    private static SecretKey getSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    private static byte[] getIV(byte[] fileData) {
        byte[] IV = new byte[BLOCK_SIZE];
        System.arraycopy(fileData, fileData.length - IV.length, IV, 0, IV.length);
        return IV;
    }

    private static byte[] xorBlock(byte[] fileData, byte[] previous) {
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
            System.arraycopy(xorBlock(cipher.doFinal(tempData[0]), (i == 0) ? IV : tempData[1]), 0, newFileData, i, tempData[0].length);
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

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] test = new byte[33];
		for(int i = 0; i < test.length; i++)
		{
			test[i] = (byte)i;
		}
		
		encrypt(test);
	}
	
	public static byte[] encrypt(byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
	{
		// Vérifier taille de la clé
		if(key.length == 24)
		{
			Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
            // Ce que je dois faire :
            
            // --> Découper mes blocs
            byte[][] nbBlocs = divideMessagesInNBlocs(plaintext);
            
            // --> Vérifier qu'il y en ai au moins 1
            if(nbBlocs.length > 0)
            {
            	// --> Générer l'IV
                SecureRandom randomSecureRandom = new SecureRandom();
                System.out.print(cipher.getBlockSize());
                byte[] iv = new byte[BLOC_SIZE_OCT];
                randomSecureRandom.nextBytes(iv);
                byte[][] cipherText = new byte[nbBlocs.length][BLOC_SIZE_OCT];
                byte[] temp = iv;
                // --> Chiffrement des blocs, opération Xor avant chaque encryption, premièrement avec l'IV puis avec le ciphertext précédent pour les prochains
                int i = 0;
                for(byte[] bloc : nbBlocs)
                {
                	byte[] resultXor = xor2Blocs(temp, bloc);
                	
                	cipherText[i] = cipher.update(resultXor);
                	
                	System.arraycopy(cipherText[i], 0, temp, 0, BLOC_SIZE_OCT);
                	i++;
                }
                
                // On recolle les blocs chiffrés dans resultat
                byte[] result = new byte[nbBlocs.length * BLOC_SIZE_OCT];
                i = 0;
                for(byte[] blocCipher : cipherText)
                {
                	System.arraycopy(blocCipher, 0, result, i * BLOC_SIZE_OCT, BLOC_SIZE_OCT);
                	i++;
                }
                return result;
            }
            else
            	return null;
		}
		else
			System.out.println("La clé doit faire une taille de 24 octets(192bits), or elle fait "+key.length+" octets");
		return null;
	}
	
	public static byte[] encryptOneBloc(byte[] bloc, Cipher cipher) throws IllegalBlockSizeException, BadPaddingException
	{
		return cipher.doFinal(bloc);
	}
	
	public static byte[][] divideMessagesInNBlocs(byte[] plaintext)
	{
		int lastMessageSize = plaintext.length % BLOC_SIZE_OCT;
		int numberFullMessages = plaintext.length / BLOC_SIZE_OCT;
		byte[][] result = null;
		// Initialisation du tableau résultat
		if(lastMessageSize > 0)
			result = new byte[numberFullMessages + 1][16];
		else
			result = new byte[numberFullMessages][16];
		
		int j = 0;
		for(int i = 0; i < plaintext.length; i++)
		{
			// On passe au bloc suivant
			if(i % BLOC_SIZE_OCT == 0 && i != 0)
				j++;
			
			result[j][i % BLOC_SIZE_OCT] = plaintext[i];
			
		}
		// Faut-il rajouter le padding à la main ?
		//OUI !!!
		if(lastMessageSize > 0) 
		{
			int padding = 16 - lastMessageSize;
			for(int i = 0; i < padding; i++)
				result[numberFullMessages][i+lastMessageSize] = (byte)padding;
		}
		return result;
	}
	
	// Fonctionne
	public static byte[] xor2Blocs(byte array1[], byte array2[])
	{
		if(array1.length == array2.length)
		{
			byte[] result = new byte[array1.length];
			int i = 0;
			for(i = 0; i < array1.length; i++)
			{
				result[i] =  xor(array1[i],array2[i]);
			}
			return result;	
		}
		else
			return null;
	}
	
	// Fonctionne
	public static byte xor(byte a, byte b)
	{
		return  (byte) (0xff &(a ^ b));
	}
}
