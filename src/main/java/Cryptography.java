import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

import at.favre.lib.crypto.HKDF;

public class Cryptography {

	// Taille clé de chiffrement en octet
	private static final int ENCRYPT_KEY_SIZE = 24;
	// Taille clé d'intégrité en octet
	private static final int MAC_KEY_SIZE = 16;
    // Taille d'un bloc en octet
    private static final int BLOCK_SIZE = 16;
    // Taille d'un mac en octet
    private static final int MAC_SIZE = 16;

    // Renvoie la clé secrète en fonction du tableau d'octets
    private static SecretKeySpec getSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    // Dérive la clé en paramètre en deux sous clés (HKDF)
    private static ArrayList<byte[]> derivateKey(byte[] masterKey) {
        // On dérive la clé maître en 2 sous clés grâce à un HKDF :
        // La clé de chiffrement utilisée par AES-192 : ENCRYPT_KEY_SIZE octets
        byte[] encKey = HKDF.fromHmacSha256().expand(masterKey, "encKey".getBytes(StandardCharsets.UTF_8), ENCRYPT_KEY_SIZE);
        // La clé d'intégrité utilisée pour calculer le CMAC : MAC_KEY_SIZE octets
        byte[] integrityKey = HKDF.fromHmacSha256().expand(masterKey, "integrityKey".getBytes(StandardCharsets.UTF_8), MAC_KEY_SIZE);
        // Renvoie nos clés
        return new ArrayList<>(Arrays.asList(masterKey, encKey, integrityKey));
    }

    // Initialise notre MAC pour le chiffrement et déchiffrement
    private static Mac initMac(byte[] integrityKey) {
        // Création du KeyParameter avec la clé d'intégrité utilisé par la lib Bounty Castle
        KeyParameter integrityKeyP = new KeyParameter(integrityKey);
        // Initialisation du cipher utilisé pour le calcul du CMAC
        BlockCipher macCipher = new AESEngine();
        // Création de l'instance du MAC en CMAC utilisant le mac Cipher et générant un MAC de MAC_SIZE octets
        Mac mac = new CMac(macCipher, MAC_SIZE * 8);
        // Initialisation du mac avec la clé d'intégrité
        mac.init(integrityKeyP);
        // Renvoie du mac
        return mac;
    }

    // Renvoie le résultat de l'opération XOR entre deux tableaux d'octets
    private static byte[] xor(byte[] fileData, byte[] previous) {
        // On vérifie si les tableaux ont la même taille
        if (fileData.length == previous.length)
            // On effectue l'opération sur chaque octet
            for (int i = 0; i < fileData.length; i++)
                // Calcul du résultat entre 2 octets
                fileData[i] = (byte) (0xff & ((int) fileData[i]) ^ ((int) previous[i]));
        // Renvoie le résultat
        return fileData;
    }

	private static byte[] encryptCTS(byte[] fileData, Cipher cipher, byte[] blockToXor) throws BadPaddingException, IllegalBlockSizeException {
        System.out.println(Arrays.toString(blockToXor));
        byte[] bLastBlock = new byte[BLOCK_SIZE];
        byte[] lastBlock = new byte[fileData.length % BLOCK_SIZE];
        System.arraycopy(fileData, fileData.length - lastBlock.length - BLOCK_SIZE, bLastBlock, 0, bLastBlock.length);
        System.arraycopy(fileData, fileData.length - lastBlock.length, lastBlock, 0, lastBlock.length);

        byte[] newBLastBlock = new byte[lastBlock.length];
        byte[] newLastBlock = new byte[bLastBlock.length];
        System.arraycopy(cipher.doFinal(xor(bLastBlock, blockToXor)), 0, newLastBlock, 0, newLastBlock.length);
        System.arraycopy(newLastBlock, 0, newBLastBlock, 0, newBLastBlock.length);
        System.arraycopy(xor(lastBlock, newBLastBlock), 0, newLastBlock, 0, lastBlock.length);
        System.arraycopy(cipher.doFinal(newLastBlock), 0, newLastBlock, 0, newLastBlock.length);

        byte[] ctsBlock = new byte[bLastBlock.length + lastBlock.length];
        System.arraycopy(newLastBlock, 0, ctsBlock, 0, newLastBlock.length);
        System.arraycopy(newBLastBlock, 0, ctsBlock, newLastBlock.length, newBLastBlock.length);
        return ctsBlock;
    }

    private static byte[] decryptCTS(byte[] fileData, Cipher cipher, byte[] blockToXor) throws BadPaddingException, IllegalBlockSizeException {
        byte[] bLastBlock = new byte[BLOCK_SIZE];
        byte[] lastBlock = new byte[fileData.length % BLOCK_SIZE];
        System.arraycopy(fileData, fileData.length - lastBlock.length - BLOCK_SIZE, bLastBlock, 0, bLastBlock.length);
        System.arraycopy(fileData, fileData.length - lastBlock.length, lastBlock, 0, lastBlock.length);

        byte[] newBLastBlock = new byte[lastBlock.length];
        byte[] newLastBlock = new byte[bLastBlock.length];
        System.arraycopy(cipher.doFinal(bLastBlock), 0, bLastBlock, 0, bLastBlock.length);
        System.arraycopy(bLastBlock, 0, newLastBlock, 0, newLastBlock.length);
        System.arraycopy(lastBlock, 0, newLastBlock, 0, lastBlock.length);
        System.arraycopy(xor(bLastBlock, newLastBlock), 0, newBLastBlock, 0, newBLastBlock.length);
        System.arraycopy(xor(cipher.doFinal(newLastBlock), blockToXor), 0, newLastBlock, 0, newLastBlock.length);

        byte[] ctsBlock = new byte[bLastBlock.length + lastBlock.length];
        System.arraycopy(newLastBlock, 0, ctsBlock, 0, newLastBlock.length);
        System.arraycopy(newBLastBlock, 0, ctsBlock, newLastBlock.length, newBLastBlock.length);
        return ctsBlock;
    }

	// Processus de chiffrement
	public static ArrayList<byte[]> encrypt(byte[] fileData, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Initialise le tableau vide du vecteur d'initialisation
        byte[] IV = new byte[BLOCK_SIZE];
        // Remplie le tableau avec des valeurs aléatoires
        new SecureRandom().nextBytes(IV);

        // Dérive notre clé en deux sous clés
        // 0 - clé maître, 1 - clé de chiffrement, 2 - clé d'intégrité
        ArrayList<byte[]> keys = derivateKey(HKDF.fromHmacSha256().expand(key, Arrays.toString(IV).getBytes(StandardCharsets.UTF_8), ENCRYPT_KEY_SIZE));

		// Initialisation de l'algorithme de chiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (chiffrement) avec initialisation de la clé
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(keys.get(1)));

		// Initialisation de deux tableaux permettant de conserver les blocs pour les étapes suivantes
		byte[][] tempData = new byte[2][BLOCK_SIZE];
        System.arraycopy(IV, 0, tempData[1], 0, tempData[1].length);

		// Détermine la taille du fichier pour appliquer ou non le CTS (CipherText Stealing)
		//int limitFileSize = fileData.length % BLOCK_SIZE == 0 ? fileData.length : fileData.length - (2 * BLOCK_SIZE);
		// Itération sur chaque bloc des données du fichier
		for (int i = 0; i < fileData.length - (2 * BLOCK_SIZE); i += BLOCK_SIZE) {
		    // Copie le bloc 'i' du fichier dans le tableau '0'
			System.arraycopy(fileData, i, tempData[0], 0, tempData[0].length);
			// Met à jour le tableau '0' avec le résultat du XOR suivi du chiffrement AES
            // S'il s'agit de la première itération alors on XOR avec l'IV sinon avec le bloc précédent
			System.arraycopy(cipher.doFinal(xor(tempData[0], (i == 0) ? IV : tempData[1])), 0, tempData[0], 0, tempData[0].length);
			// On sauvegarde le résultat dans le tableau '1' pour le tour suivant
			System.arraycopy(tempData[0], 0, tempData[1], 0, tempData[0].length);
			// Renvoie le tableau '0' dans le tableau d'origine (contenant les données du fichier)
			System.arraycopy(tempData[0], 0, fileData, i, tempData[0].length);
		}

		//if (limitFileSize % BLOCK_SIZE != 0) {
		    byte[] ctsBlock = encryptCTS(fileData, cipher, tempData[1]);
            System.arraycopy(ctsBlock, 0, fileData, fileData.length - ctsBlock.length, ctsBlock.length);
        //}

        // Création de l'instance du MAC
        Mac mac = initMac(keys.get(2));
        // Préparation du CMAC avec les données suivantes : ciphertext || iv
        mac.update(fileData, 0, fileData.length);
        // Initialisation du tableau qui récupérera le CMAC
        byte[] macResult = new byte[mac.getMacSize()];
        // Calcul du CMAC et nous donne le résultat dans le tableau macResult
        mac.doFinal(macResult, 0);

        // Tableau d'octets contenant l'IV et le MAC du fichier
        byte[] encryptData = new byte[BLOCK_SIZE * 2];
		// On sauvegarde l'IV du fichier
		System.arraycopy(IV, 0, encryptData, 0, IV.length);
		// On sauvegarde le CMAC du fichier
		System.arraycopy(macResult, 0, encryptData, IV.length, macResult.length);
		
		// On efface les données des clés en mémoire
		Arrays.fill(keys.get(0), (byte) 0);
		Arrays.fill(keys.get(1), (byte) 0);
		Arrays.fill(keys.get(2), (byte) 0);

		// Renvoie les nouvelles données du fichier chiffré
        return new ArrayList<>(Arrays.asList(fileData, encryptData));
	}

    // Processus de déchiffrement
    public static byte[] decrypt(byte[] fileData, byte[] key, byte[] encryptData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, FileIntegrityException {
        // Récupération de l'IV à partir du tableau 'encryptData'
        byte[] IV = new byte[BLOCK_SIZE];
        System.arraycopy(encryptData, 0, IV, 0, IV.length);
        // Récupération du CMAC à partir du tableau 'encryptData'
        byte[] receivedMAC = new byte[BLOCK_SIZE];
        System.arraycopy(encryptData, IV.length, receivedMAC, 0, receivedMAC.length);

        // Dérive notre clé en deux sous clés
        // 0 - clé maître, 1 - clé de chiffrement, 2 - clé d'intégrité
        ArrayList<byte[]> keys = derivateKey(HKDF.fromHmacSha256().expand(key, Arrays.toString(IV).getBytes(StandardCharsets.UTF_8), ENCRYPT_KEY_SIZE));
    	
        // Initialisation de l'algorithme de déchiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (déchiffrement) avec initialisation de la clé
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(keys.get(1)));

        // Création de l'instance du MAC
        Mac mac = initMac(keys.get(2));
		// Préparation du CMAC avec les données suivantes : ciphertext || iv
		mac.update(fileData, 0, fileData.length);
		// Initialisation du tableau qui récupérera le CMAC
		byte[] macResult = new byte[mac.getMacSize()];
		// Calcul du CMAC et nous donne le résultat dans le tableau macResult
		mac.doFinal(macResult, 0);
  		
  		// On compare le CMAC récupéré dans le fichier et celui calculé
        // Si c'est le même, on peut déchiffrer le ciphertext
        // Sinon, problème d'intégrité, le ciphertext et/ou l'IV ont été altéré
		try {
            if (!MessageDigest.isEqual(receivedMAC, macResult))
                throw new FileIntegrityException();
        } catch (Exception e) { System.exit(0); }

        // Tableau permettant de garder une copie du bloc pendant le processus
        byte[] tampon = new byte[BLOCK_SIZE];
        // Initialisation de deux tableaux permettant de conserver les blocs pour les étapes suivantes
        byte[][] tempData = new byte[2][BLOCK_SIZE];
        System.arraycopy(IV, 0, tempData[1], 0, tempData[1].length);

        // Détermine la taille du fichier pour appliquer le CTS (CipherText Stealing)
        //int limitFileSize = fileData.length % BLOCK_SIZE == 0 ? fileData.length : fileData.length - (2 * BLOCK_SIZE);
        // Itération sur chaque bloc des données du fichier
        for (int i = 0; i < fileData.length - (2 * BLOCK_SIZE); i += BLOCK_SIZE) {
            // Copie le bloc 'i' du fichier dans le tableau '0'
            System.arraycopy(fileData, i, tempData[0], 0, tempData[0].length);
            // Copie le bloc 'i' du fichier dans le tableau 'tampon'
            System.arraycopy(fileData, i, tampon, 0, tampon.length);
            // Met à jour les données fu fichier avec le chiffrement AES suivi du résultat du XOR
            // S'il s'agit de la première itération alors on XOR avec l'IV sinon avec le bloc précédent
            System.arraycopy(xor(cipher.doFinal(tempData[0]), (i == 0) ? IV : tempData[1]), 0, fileData, i, tempData[0].length);
            // Récupère le bloc sauvegardé dans tampon pour l'utiliser au prochain tour
            System.arraycopy(tampon, 0, tempData[1], 0, tempData[1].length);
        }

        //if (limitFileSize % BLOCK_SIZE != 0) {
            byte[] ctsBlock = decryptCTS(fileData, cipher, tempData[1]);
            System.arraycopy(ctsBlock, 0, fileData, fileData.length - ctsBlock.length, ctsBlock.length);
        //}
        
        // On efface les données des clés en mémoire
 		Arrays.fill(keys.get(0), (byte) 0);
 		Arrays.fill(keys.get(1), (byte) 0);
 		Arrays.fill(keys.get(2), (byte) 0);

        // Renvoie les données déchiffrées sans le padding
        return fileData;
    }

    // Transforme une chaîne de caractères (hexadécimaux) en tableau d'octets
    public static byte[] hexStringToByteArray(String hex) {
        // Initialisation d'un nouveau tableau avec une taille 2 fois moins grande que celle de la chaîne en paramètre
        byte[] data = new byte[hex.length()/2];
        // Remplis le nouveau tableau d'octets
        for (int i = 0; i < hex.length(); i += 2)
            // Change la valeur hexadécimale en octet
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), BLOCK_SIZE) << 4) + Character.digit(hex.charAt(i+1), BLOCK_SIZE));
        // Renvoie le tableau d'octets
        return data;
    }
}
