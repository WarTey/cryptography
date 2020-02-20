import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Cryptography {

    // Taille d'un bloc
    private static final int BLOCK_SIZE = 16;

    // Renvoie la clé secrète en fonction du tableau d'octets
    private static SecretKeySpec getSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    // Renvoie le vecteur d'initialisation stocké dans les données du fichier
    private static byte[] getIV(byte[] fileData) {
        // Initialisation du vecteur d'initialisation avec la taille correspondante
        byte[] IV = new byte[BLOCK_SIZE];
        // Récupération de ce dernier dans les données du fichier (les 16 derniers octets)
        System.arraycopy(fileData, fileData.length - IV.length, IV, 0, IV.length);
        // Renvoie de l'IV
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
        // Renvoie du résultat
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
        // Renvoie des nouvelles données
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
	public static byte[] encrypt(byte[] fileData, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		// Initialisation de l'algorithme de chiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (chiffrement) avec initialisation de la clé
		cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(hexStringToByteArray(key)));

		// Initialise le tableau vide du vecteur d'initialisation
    	byte[] IV = new byte[BLOCK_SIZE];
    	// Remplit le tableau avec des valeurs aléatoires
		new SecureRandom().nextBytes(IV);

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
			// Renvoie du tableau '0' dans le tableau d'origine (contenant les données du fichier)
			System.arraycopy(tempData[0], 0, newFileData, i, tempData[0].length);
		}

		// Initialisation d'un nouveau tableau pour les données chiffrées plus l'IV
		byte[] newFileDataIV = new byte[newFileData.length + BLOCK_SIZE];
		// On copie les données du fichier chiffrées dans ce nouveau tableau
		System.arraycopy(newFileData, 0, newFileDataIV, 0, newFileData.length);
		// On ajoute l'IV à la fin
		System.arraycopy(IV, 0, newFileDataIV, newFileData.length, IV.length);
		// On renvoie le contenu du tableau précédent
		return newFileDataIV;
	}

    // Processus de déchiffrement
    public static byte[] decrypt(byte[] fileData, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Initialisation de l'algorithme de déchiffrement
        // Ici ECB mais application des étapes nécessaires pour faire un CBC avec un padding
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        // Choix du type (déchiffrement) avec initialisation de la clé
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(hexStringToByteArray(key)));

        // Récupération de l'IV à la fin des données chiffrées
        byte[] IV = getIV(fileData);
        // Initialisation d'un tableau pour les données chiffrées sans l'IV
		byte[] newFileData = new byte[fileData.length - BLOCK_SIZE];
		// Copie les données chiffrées sans l'IV
        System.arraycopy(fileData, 0, newFileData, 0, newFileData.length);

        // Tableau permettant de garder une copie du copie pendant le processus
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
            // Récupère le bloc sauvegarder dans tampon pour l'utilser au prochain tour
            System.arraycopy(tampon, 0, tempData[1], 0, tempData[1].length);
        }
        // Renvoie les données déchiffrées sans le padding
        return removePadding(newFileData);
    }

    // Transforme une chaîne de caractère (hexadécimal) en tableau d'octets
    public static byte[] hexStringToByteArray(String hex) {
        // Initialisation d'un nouveau tableau avec une taille 2 fois moins grande que celle de la chaîne en paramètre
        byte[] data = new byte[hex.length()/2];
        // Remplit le nouveau tableau d'octets
        for (int i = 0; i < hex.length(); i += 2)
            // Change la valeur hexadécimal en octet
            data[i/2] = (byte) ((Character.digit(hex.charAt(i), BLOCK_SIZE) << 4) + Character.digit(hex.charAt(i+1), BLOCK_SIZE));
        // Renvoie le tableau d'octets
        return data;
    }
}
