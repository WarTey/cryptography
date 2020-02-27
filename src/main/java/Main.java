import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {

    // Taille d'un bloc en octet
    private static final int BLOCK_SIZE = 16;

    private static void process(ArrayList<String> inputFiles, File fileOutput, String encryptionType, String key) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, FileIntegrityException {
        // Initialise le tableau contenant l'ensemble des données chiffrées ou déchiffrées
        ArrayList<byte[]> filesData = new ArrayList<>();
        // Initialise un tableau d'octets qui contiendra les données nécessaires au déchiffrement
        byte[] encryptData = new byte[BLOCK_SIZE * 2 * inputFiles.size()];
        // Parcourt les fichiers d'entrées
        for (int i = 0; i < inputFiles.size(); i++) {
            // Initialise le fichier d'entrée
            File fileInput = new File(inputFiles.get(i));
            // Récupère les données du fichier
            byte[] fileData = Files.readAllBytes(fileInput.toPath());
            // Selon le mode choisi dans les arguments, lance le chiffrement ou déchiffrement
            // Sauvegarde de plus le résultat dans le tableau précédemment créé
            if (encryptionType.equals("encryption")) {
                ArrayList<byte[]> encryptResult = Cryptography.encrypt(fileData, Cryptography.hexStringToByteArray(key), i);
                filesData.add(encryptResult.get(0));
                System.arraycopy(encryptResult.get(1), 0, encryptData, i * BLOCK_SIZE * 2, encryptResult.get(1).length);
            } else if (encryptionType.equals("decryption"))
                filesData.add(Cryptography.decrypt(fileData, Cryptography.hexStringToByteArray(key)));
        }
        // Crée l'archive avec les données précédentes
        FileManager.createArchive(inputFiles, filesData, fileOutput, encryptData);
        System.out.println("Fin d'exécution.");
    }

    public static void main(String[] args) throws Exception {
        // Récupère les arguments (type de chiffrement, clé, fichier d'entrée et de sortie)
        String encryptionType = Arguments.getEncryptionType(args);
        String key = Arguments.getKey(args);
        ArrayList<String> inputFiles = Arguments.getInputFile(args);
        String outputFile = Arguments.getOutputFile(args);

        // Vérifie que les arguments existent
        if (encryptionType != null && key != null && inputFiles != null && outputFile != null) {
            // Initialise le fichier de sortie
            File fileOutput = new File(outputFile + ".zip");

            // Vérifie que les fichiers d'entrées soient corrects
            if (FileManager.isInputFilesReady(inputFiles, outputFile)) {
                // Vérifie que le fichier de sortie n'existe pas
                if (!fileOutput.exists())
                    // Lance de processus de chiffrement/déchiffrement
                    process(inputFiles, fileOutput, encryptionType, key);
                else {
                    // Vérifie si le fichier de sortie est un fichier
                    if (fileOutput.isFile()) {
                        String answer;
                        do {
                            // Demande à l'utilisateur s'il est possible d'écraser le fichier de sortie
                            System.out.println("Attention, le fichier de sortie existe déjà. Voulez-vous l'écraser? (Y/N)");
                            // Récupère l'entrée de l'utilisateur
                            answer = new Scanner(System.in).next();
                        } while (!answer.equals("Y") && !answer.equals("N"));
                        // Selon sa réponse lance le processus ou arrête de programme
                        if (answer.equals("Y") && fileOutput.isFile())
                            process(inputFiles, fileOutput, encryptionType, key);
                        else
                            System.out.println("Processus interrompu.");
                    } else
                        System.out.println("Attention, le fichier de sortie est un dossier.");
                }
            } else
                // Affiche un message d'erreur
                System.out.println("Attention, un des fichiers d'entrées n'existe pas, est un dossier ou correspond au fichier de sortie ou à un des fichiers d'entrées.");
        } else
            // Affiche un message d'aide si les arguments sont incorrects
            System.out.println(Arguments.helpArguments());
    }
}
