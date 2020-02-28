import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    // Taille d'un bloc en octet
    private static final int BLOCK_SIZE = 16;

    private static void process(ArrayList<String> inputFiles, File fileOutput, String encryptionType, String key) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, FileIntegrityException {
        // Initialise le tableau contenant l'ensemble des données chiffrées ou déchiffrées
        ArrayList<byte[]> filesData = new ArrayList<>();

        if (encryptionType.equals("encryption")) {
            // Initialise un tableau d'octets qui contiendra les données nécessaires au déchiffrement
            byte[] encryptData = new byte[BLOCK_SIZE * 2 * inputFiles.size()];
            // Parcourt les fichiers d'entrées
            for (int i = 0; i < inputFiles.size(); i++) {
                // Initialise le fichier d'entrée
                File fileInput = new File(inputFiles.get(i));
                // Récupère les données du fichier
                byte[] fileData = Files.readAllBytes(fileInput.toPath());
                // Récupère les données du fichier chiffrées ainsi que son IV et MAC
                ArrayList<byte[]> encryptResult = Cryptography.encrypt(fileData, Cryptography.hexStringToByteArray(key));
                // Sauvegarde les données chiffrées dans le tableau 'filesData'
                filesData.add(encryptResult.get(0));
                // Sauvegarde l'IV et MAC dans le tableau 'encryptData'
                System.arraycopy(encryptResult.get(1), 0, encryptData, i * BLOCK_SIZE * 2, encryptResult.get(1).length);
            }
            // Crée l'archive avec les données précédentes
            FileManager.createArchive(inputFiles, filesData, fileOutput, encryptData);
        } else if (encryptionType.equals("decryption")) {
            if (fileOutput.mkdir()) {
                FileManager.extractArchive(inputFiles.get(0), fileOutput.getPath());
                ArrayList<String> names = FileManager.extractNamesFromArchive(new File(inputFiles.get(0)));
                File fileEncrypt = new File(fileOutput.getPath() + File.separator + names.get(names.size() - 1));
                byte[] encryptsData = Files.readAllBytes(fileEncrypt.toPath());
                byte[] encryptData = new byte[BLOCK_SIZE * 2];
                for (int i = 0; i < names.size() - 1; i++) {
                    File fileInput = new File(fileOutput.getPath() + File.separator + names.get(i));
                    byte[] fileData = Files.readAllBytes(fileInput.toPath());
                    System.arraycopy(encryptsData, i * BLOCK_SIZE * 2, encryptData, 0, encryptData.length);
                    Files.write(fileInput.toPath(), Cryptography.decrypt(fileData, Cryptography.hexStringToByteArray(key), encryptData));
                }
                new File(fileOutput.getPath() + File.separator + names.get(names.size() - 1)).delete();
            } else
                System.out.println("Une erreur est survenue lors de la création du dossier.");
        }
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
            File fileOutput = new File(outputFile);

            // Vérifie que les fichiers d'entrées soient corrects
            if (FileManager.isInputFilesReady(inputFiles, fileOutput, encryptionType)) {
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
            }
        } else
            // Affiche un message d'aide si les arguments sont incorrects
            System.out.println(Arguments.helpArguments());
    }
}
