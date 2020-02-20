import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Cryptography {
	
	private static SecretKeySpec secretKey;
    private static byte[] key  = {(byte)0xB2,(byte)0x0A,(byte)0xDE,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11,(byte)0x11};
    private static final int BLOC_SIZE_OCT = 16;
    
	public Cryptography() {
		
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
