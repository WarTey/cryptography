import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Cryptography {
	
	private static SecretKeySpec secretKey;
    private static byte[] key;
    private static final int BLOC_SIZE_OCT = 16;
    
	public Cryptography() {
		
	}

	public static void main(String[] args) {
		byte[] test = new byte[36];
		for(int i = 0; i < test.length; i++)
		{
			test[i] = (byte)i;
		}
		divideMessagesInNBlocs(test);

	}
	
	public static byte[] encrypt(byte[] plaintext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException
	{
		// Vérifier taille de la clé
		if(key.length == 24)
		{
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            
		}
		else
			System.out.println("La clé doit faire une taille de 24 octets(192bits), or elle fait "+key.length+" octets");
		return null;
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
		return result;
	}
}
