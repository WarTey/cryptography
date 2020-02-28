import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Main {

    private static void process(ArrayList<String> inputFiles, File fileOutput, String encryptionType, String key) throws IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, FileIntegrityException {
        if (encryptionType.equals("encryption")) {
            // Initialise le tableau contenant l'ensemble des données chiffrées
            ArrayList<byte[]> filesData = new ArrayList<>();
            // Initialise un tableau d'octets qui contiendra les données nécessaires au déchiffrement
            byte[] encryptData = new byte[Cryptography.BLOCK_SIZE * 2 * inputFiles.size()];
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
                System.arraycopy(encryptResult.get(1), 0, encryptData, i * Cryptography.BLOCK_SIZE * 2, encryptResult.get(1).length);
            }
            // Crée l'archive avec les données précédentes
            FileManager.createArchive(inputFiles, filesData, fileOutput, encryptData);
        } else if (encryptionType.equals("decryption")) {
            // Crée le dossier qui contiendra les fichiers déchiffrés
            if (fileOutput.mkdir()) {
                // Extrait l'archive dans le dossier précédent
                FileManager.extractArchive(inputFiles.get(0), fileOutput.getPath());
                // Récupère les noms des fichiers à partir de l'archive (pour conserver l'ordre des fichiers)
                ArrayList<String> names = FileManager.extractNamesFromArchive(new File(inputFiles.get(0)));
                // Récupère le fichier contenant les informations de déchiffrement (IV et MAC)
                File fileEncrypt = new File(fileOutput.getPath() + File.separator + names.get(names.size() - 1));
                // Récupère les octets du fichier précédent
                byte[] encryptsData = Files.readAllBytes(fileEncrypt.toPath());
                // Initialise un tableau qui contiendra les informations de déchiffrement d'un fichier
                byte[] encryptData = new byte[Cryptography.BLOCK_SIZE * 2];
                // On itère sur chaque nom de fichier (sauf le dernier)
                for (int i = 0; i < names.size() - 1; i++) {
                    // Initialise le fichier
                    File fileInput = new File(fileOutput.getPath() + File.separator + names.get(i));
                    // Récupère les données du fichier
                    byte[] fileData = Files.readAllBytes(fileInput.toPath());
                    // Récupère les informations de déchiffrement de ce fichier
                    System.arraycopy(encryptsData, i * Cryptography.BLOCK_SIZE * 2, encryptData, 0, encryptData.length);
                    // Déchiffrement le fichier et le sauvegarde dans le dossier
                    Files.write(fileInput.toPath(), Cryptography.decrypt(fileData, Cryptography.hexStringToByteArray(key), encryptData));
                }
                // Supprime le fichier contenant les informations de déchiffrement
                fileEncrypt.deleteOnExit();
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

            // Vérifie que le fichier de sortie et les fichiers d'entrées
            if (FileManager.isInputFilesReady(inputFiles, encryptionType) && FileManager.isOutputFilesReady(fileOutput, encryptionType))
                // Lance de processus de chiffrement/déchiffrement
                process(inputFiles, fileOutput, encryptionType, key);
        } else
            // Affiche un message d'aide si les arguments sont incorrects
            System.out.println(Arguments.helpArguments());
    }
}
