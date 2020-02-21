import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {

    // Renvoie l'aide pour les arguments
    private static String helpArguments () {
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
        errorMessage += space + "-out: output file (different from the input file)\n";
        // Renvoie du message d'aide
        return errorMessage;
    }

    private static void process(File fileInput, File fileOutput, String encryptionType, String key) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        // Récupère les données du fichier
        byte[] fileData = Files.readAllBytes(fileInput.toPath());
        // Selon le mode choisi dans les arguments, lance le chiffrement ou déchiffrement
        // Écrit de plus le résultat dans le fichier de sortie
        if (encryptionType.equals("encryption"))
            Files.write(fileOutput.toPath(), Cryptography.encrypt(fileData, key));
        else if (encryptionType.equals("decryption"))
            Files.write(fileOutput.toPath(), Cryptography.decrypt(fileData, key));
        System.out.println("Fin d'exécution.");
    }

    public static void main(String[] args) throws Exception {
        // Récupère les arguments (type de chiffrement, clé, fichier d'entrée et de sortie)
        String encryptionType = Arguments.getEncryptionType(args);
        String key = Arguments.getKey(args);
        String inputFile = Arguments.getFile(args, true);
        String outputFile = Arguments.getFile(args, false);

        // Vérifie que les arguments existe
        if (encryptionType != null && key != null && inputFile != null && outputFile != null && !inputFile.equals(outputFile)) {
            // Initialise le fichier d'entrée et de sortie
            File fileInput = new File(inputFile);
            File fileOutput = new File(outputFile);
            // Vérifie que le fichier d'entrée existe
            if (fileInput.exists()) {
                // Vérifie que le fichier de sortie n'existe pas
                if (!fileOutput.exists())
                    // Lance de processus de chiffrement/déchiffrement
                    process(fileInput, fileOutput, encryptionType, key);
                else {
                    String answer;
                    // Demande à l'utilisateur s'il est possible d'écraser le fichier de sortie
                    do {
                        System.out.println("Attention, le fichier de sortie existe déjà. Voulez-vous l'écraser? (Y/N)");
                        // Récupère l'entrée de l'utilisateur
                        answer = new Scanner(System.in).next();
                    } while (!answer.equals("Y") && !answer.equals("N"));
                    // Selon sa réponse lance le processus ou arrête de programme
                    if (answer.equals("Y"))
                        process(fileInput, fileOutput, encryptionType, key);
                    else
                        System.out.println("Processus interrompu.");
                }
            } else
                // Affiche un message si le fichier d'entrée n'existe pas
                System.out.println("Attention, le fichier d'entrée n'existe pas.");
        } else
            // Affiche un message d'aide si les arguments sont incorrects
            System.out.println(helpArguments());
    }
}
