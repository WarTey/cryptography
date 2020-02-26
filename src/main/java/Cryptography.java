import java.nio.charset.StandardCharsets;
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

    // Renvoie le MAC stocké dans les données du fichier
    private static byte[] getMAC(byte[] fileData) {
        // Initialisation du MAC avec la taille correspondante
        byte[] MAC = new byte[MAC_SIZE];
        // Récupération de ce dernier dans les données du fichier (situé à la fin de fileData)
        System.arraycopy(fileData, fileData.length - MAC.length, MAC, 0, MAC.length);
        // Renvoie le MAC
        return MAC;
    }
    
    // Renvoie le vecteur d'initialisation stocké dans les données du fichier
    private static byte[] getIV(byte[] fileData) {
        // Initialisation du vecteur d'initialisation avec la taille correspondante
        byte[] IV = new byte[BLOCK_SIZE];
        // Récupération de ce dernier dans les données du fichier (situé avant le MAC dans filedata)
        System.arraycopy(fileData, fileData.length - IV.length - MAC_SIZE, IV, 0, IV.length);
        // Renvoie l'IV
        return IV;
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

    // Supprime le padding des données du fichier
    private static byte[] removePadding(byte[] fileData) {
        // Détermine la taille du padding (qui est aussi la valeur des valeurs stockées)
        int paddingValue = fileData[fileData.length - 1];
        // On vérifie que les valeurs précédentes soient bien égales à la taille du padding
        // On remonte de n fois où n correspond à la valeur du padding
        for (int i = fileData.length - paddingValue; i < fileData.length; i++)
            // On renvoie le tableau sans modification si une valeur est différente
            if (fileData[i] != paddingValue)
                return fileData;

        // Initialisation d'un nouveau tableau avec la taille du précédent moins la valeur du padding
        byte[] newFileData = new byte[fileData.length - paddingValue];
        // Copie des données du fichier sans le padding
        System.arraycopy(fileData, 0, newFileData, 0, newFileData.length);
        // Renvoie les nouvelles données
        return newFileData;
    }

    // Ajoute un padding aux données du fichier
    private static byte[] addPadding(byte[] fileData) {
        // Calcul de la taille du padding
		int paddingValue = BLOCK_SIZE - (fileData.length % BLOCK_SIZE);
        // Initialisation d'un nouveau tableau avec la taille des données plus la valeur du padding
		byte[] newFileData = new byte[fileData.length + paddingValue];
		// Copie des données du fichier dans ce tableau
		System.arraycopy(fileData, 0, newFileData, 0, fileData.length);
		// Ajoute les valeurs du padding à la fin des données
		for (int i = fileData.length; i < fileData.length + paddingValue; i++)
			newFileData[i] = (byte) (0xff & paddingValue);
		// Renvoie les nouvelles données
		return newFileData;
	}

	// Processus de chiffrement
	public static byte[] encrypt(byte[] fileData, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Initialise le tableau vide du vecteur d'initialisation
        byte[] IV = new byte[BLOCK_SIZE];
        // Remplie le tableau avec des valeurs aléatoires
        new SecureRandom().nextBytes(IV);

        // Dérive notre clé en deux sous clés
        // 0 - clé maître, 1 - clé de chiffrement, 2 - clé d'intégrité
        ArrayList<byte[]> keys = derivateKey(HKDF.fromHmacSha256().expand(key, Arrays.toString(IV).getBytes(StandardCharsets.UTF_8), ENCRYPT_KEY_SIZE));

        // Création de l'instance du MAC
        Mac mac = initMac(keys.get(2));

		// Initialisation de l'algorithme de chiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (chiffrement) avec initialisation de la clé
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(keys.get(1)));

		// Initialisation d'un tableau avec les données du fichier plus le padding
		byte[] newFileData = addPadding(fileData);
		// Initialisation de deux tableaux permettant de conserver les blocs pour les étapes suivantes
		byte[][] tempData = new byte[2][BLOCK_SIZE];
		// Itération sur chaque bloc des données du fichier
		for (int i = 0; i < newFileData.length; i += BLOCK_SIZE) {
		    // Copie le bloc 'i' du fichier dans le tableau '0'
			System.arraycopy(newFileData, i, tempData[0], 0, tempData[0].length);
			// Met à jour le tableau '0' avec le résultat du XOR suivi du chiffrement AES
            // S'il s'agit de la première itération alors on XOR avec l'IV sinon avec le bloc précédent
			System.arraycopy(cipher.doFinal(xor(tempData[0], (i == 0) ? IV : tempData[1])), 0, tempData[0], 0, tempData[0].length);
			// On sauvegarde le résultat dans le tableau '1' pour le tour suivant
			System.arraycopy(tempData[0], 0, tempData[1], 0, tempData[0].length);
			// Renvoie le tableau '0' dans le tableau d'origine (contenant les données du fichier)
			System.arraycopy(tempData[0], 0, newFileData, i, tempData[0].length);
		}

		// Initialisation d'un nouveau tableau pour les données chiffrées plus l'IV
		byte[] newFileDataIV = new byte[newFileData.length + BLOCK_SIZE];
		// On copie les données du fichier chiffrées dans ce nouveau tableau
		System.arraycopy(newFileData, 0, newFileDataIV, 0, newFileData.length);
		// On ajoute l'IV à la fin
		System.arraycopy(IV, 0, newFileDataIV, newFileData.length, IV.length);
		
		// Préparation du CMAC avec les données suivantes : ciphertext || iv
		mac.update(newFileDataIV, 0, newFileDataIV.length);
		// Initialisation du tableau qui récupérera le CMAC
		byte[] macResult = new byte[mac.getMacSize()];
		// Calcul du CMAC et nous donne le résultat dans le tableau macResult
		mac.doFinal(macResult, 0);

		// Initialisation d'un nouveau tableau qui contiendra les données chiffrées, l'IV et le CMAC
		byte[] newFileDataIVMac = new byte[newFileDataIV.length + MAC_SIZE];
		
		// Copie du ciphertext et IV dans ce nouveau tableau
		System.arraycopy(newFileDataIV, 0, newFileDataIVMac, 0, newFileDataIV.length);
		// Copie du CMAC à la fin du tableau
		System.arraycopy(macResult, 0, newFileDataIVMac, newFileDataIV.length, macResult.length);
		
		// On efface les données des clés en mémoire
		Arrays.fill(keys.get(0), (byte) 0);
		Arrays.fill(keys.get(1), (byte) 0);
		Arrays.fill(keys.get(2), (byte) 0);

		// Renvoie les nouvelles données du fichier chiffré
		return newFileDataIVMac;
	}

    // Processus de déchiffrement
    public static byte[] decrypt(byte[] fileData, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, FileIntegrityException {
        // Récupération de l'IV à la fin des données chiffrées
        byte[] IV = getIV(fileData);
        // Récupération du CMAC
        byte[] receivedMAC = getMAC(fileData);

        // Dérive notre clé en deux sous clés
        // 0 - clé maître, 1 - clé de chiffrement, 2 - clé d'intégrité
        ArrayList<byte[]> keys = derivateKey(HKDF.fromHmacSha256().expand(key, Arrays.toString(IV).getBytes(StandardCharsets.UTF_8), ENCRYPT_KEY_SIZE));

        // Création de l'instance du MAC
        Mac mac = initMac(keys.get(2));
    	
        // Initialisation de l'algorithme de déchiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (déchiffrement) avec initialisation de la clé
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(keys.get(1)));
        
        // Récupération du ciphertext et de l'IV
        byte[] cipherTextAndIV = new byte[fileData.length - MAC_SIZE];
        System.arraycopy(fileData, 0, cipherTextAndIV, 0, fileData.length - MAC_SIZE);

		// Préparation du CMAC avec les données suivantes : ciphertext || iv
		mac.update(cipherTextAndIV,0,cipherTextAndIV.length);
		// Initialisation du tableau qui récupérera le CMAC
		byte[] macResult = new byte[mac.getMacSize()];
		// Calcul du CMAC et nous donne le résultat dans le tableau macResult
		mac.doFinal(macResult, 0);
  		
  		// On compare le CMAC récupéré dans le fichier et celui calculé
            // si c'est le même on peut déchiffrer le ciphertext
            // sinon : probleme d'intégrité, le ciphertext et/ou l'IV a été altéré, ce n'est pas la peine de tenter de déchiffrer ce fichier, il faut le redemander
		try {
            if (!MessageDigest.isEqual(receivedMAC, macResult))
                throw new FileIntegrityException();
        } catch (Exception e) { System.exit(0); }
		
        // Initialisation d'un tableau pour les données chiffrées sans l'IV
		byte[] newFileData = new byte[fileData.length - BLOCK_SIZE - MAC_SIZE];
		// Copie les données chiffrées sans l'IV
        System.arraycopy(fileData, 0, newFileData, 0, newFileData.length);

        // Tableau permettant de garder une copie du bloc pendant le processus
        byte[] tampon = new byte[BLOCK_SIZE];
        // Initialisation de deux tableaux permettant de conserver les blocs pour les étapes suivantes
        byte[][] tempData = new byte[2][BLOCK_SIZE];
        // Itération sur chaque bloc des données du fichier
        for (int i = 0; i < newFileData.length; i += BLOCK_SIZE) {
            // Copie le bloc 'i' du fichier dans le tableau '0'
            System.arraycopy(newFileData, i, tempData[0], 0, tempData[0].length);
            // Copie le bloc 'i' du fichier dans le tableau 'tampon'
            System.arraycopy(newFileData, i, tampon, 0, tampon.length);
            // Met à jour les données fu fichier avec le chiffrement AES suivi du résultat du XOR
            // S'il s'agit de la première itération alors on XOR avec l'IV sinon avec le bloc précédent
            System.arraycopy(xor(cipher.doFinal(tempData[0]), (i == 0) ? IV : tempData[1]), 0, newFileData, i, tempData[0].length);
            // Récupère le bloc sauvegardé dans tampon pour l'utiliser au prochain tour
            System.arraycopy(tampon, 0, tempData[1], 0, tempData[1].length);
        }
        
        // On efface les données des clés en mémoire
 		Arrays.fill(keys.get(0), (byte) 0);
 		Arrays.fill(keys.get(1), (byte) 0);
 		Arrays.fill(keys.get(2), (byte) 0);

        // Renvoie les données déchiffrées sans le padding
        return removePadding(newFileData);
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
