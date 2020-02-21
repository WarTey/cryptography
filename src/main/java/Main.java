import java.util.Arrays;

public class Main {

    // Renvoie l'aide pour les arguments
    public static String helpArguments () {
        String space = "    ";
        // Exemple d'usage: filecrypt -enc|-dec -key K..K -in <input file> -out <output file>
        String errorMessage = "Example usage:\n";
        errorMessage += space + "filecrypt -enc|-dec -key K..K -in <input file> -out <output file>\n\n";
        // Description des arguments (à quoi ils correspondent)
        errorMessage += "Arguments:\n";
        errorMessage += space + "-enc: encryption\n";
        errorMessage += space + "-dec: decryption\n";
        errorMessage += space + "-key: secret key (48 characters)\n";
        errorMessage += space + "-in: input file\n";
        errorMessage += space + "-out: output file\n";
        // Renvoie du message d'aide
        return errorMessage;
    }

    public static void main(String[] args) throws Exception {
        // Récupère les arguments (type de chiffrement, clé, fichier d'entrée et de sortie)
        String encryptionType = Arguments.getEncryptionType(args);
        String key = Arguments.getKey(args);
        String inputFile = Arguments.getFile(args, true);
        String outputFile = Arguments.getFile(args, false);

        // Vérifie que les arguments existe
        if (encryptionType != null && key != null && inputFile != null && outputFile != null) {
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
        } else
            // Affiche un message d'aide si les arguments sont incorrects
            System.out.println(helpArguments());
    }
}
