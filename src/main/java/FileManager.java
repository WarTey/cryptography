import java.io.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class FileManager {

    // Nom réservé au chiffrement
    private static final String RESERVED_NAME = "EncryptData";

    // Détermine si le fichier en paramètre est une archive
    private static Boolean isArchive(File file) {
        // Contiendra la signature du fichier
        int fileSignature = 0;
        // Tente d'ouvrir le fichier en lecture
        try (RandomAccessFile randomAccessFile = new RandomAccessFile(file, "r")) {
            // Récupère la signature du fichier
            fileSignature = randomAccessFile.readInt();
        } catch (IOException e) {
            System.out.println("Attention, une erreur est survenue lors de la vérification de l'archive.");
        }
        // Retourne 'true' selon la signature du fichier
        return fileSignature == 0x504B0304 || fileSignature == 0x504B0506 || fileSignature == 0x504B0708;
    }

    // Vérifie l'ensemble des fichiers d'entrées
    public static Boolean isInputFilesReady(ArrayList<String> inputFiles, String encryptionType) {
        // Détermine si le fichier est une archive pour le déchiffrement
        if (encryptionType.equals("decryption") && !isArchive(new File(inputFiles.get(0)))) {
            // Affiche un message d'erreur et quitte le programme
            System.out.println("Attention, lors d'un déchiffrement, le paramètre d'entrée doit être une archive.");
            return false;
        }

        // Tableau permettant de contenir les noms de fichiers et ainsi éviter les doublons
        HashSet<String> duplicate = new HashSet<>();
        // Parcourt les fichiers d'entrées
        for (String inputFile : inputFiles) {
            // Initialise un des fichiers d'entrées
            File fileInput = new File(inputFile);
            // Vérifie que le fichier existe, ne soit pas un dossier, ne soit pas un doublon et qu'il soit différent du fichier de sortie
            if (!fileInput.exists()) {
                // Le fichier n'existe pas
                System.out.println("Attention, un des fichiers d'entrées n'existe pas (" + fileInput.getName() + ").");
                return false;
            } else if (!fileInput.isFile()) {
                // Le fichier est un dossier
                System.out.println("Attention, un des fichiers d'entrées est un dossier (" + fileInput.getName() + ").");
                return false;
            } else if (duplicate.contains(fileInput.getName())) {
                // Le fichier est un doublon
                System.out.println("Attention, un des fichiers d'entrées est un doublon (" + fileInput.getName() + ").");
                return false;
            } else if (fileInput.getName().equals(RESERVED_NAME)) {
                // Le fichier utilise un nom réservé
                System.out.println("Attention, un des fichiers d'entrées utilise un nom réservé (" + fileInput.getName() + ").");
                return false;
            } else duplicate.add(fileInput.getName());
        }
        // Les fichiers sont corrects
        return true;
    }

    // Crée une archive à partir des nouvelles données
    public static void createArchive(ArrayList<String> inputFiles, ArrayList<byte[]> filesData, File fileOutput, byte[] encryptData) throws IOException {
        // Initialise le flux de sortie permettant d'écrire dans le fichier
        FileOutputStream fileOutputStream = new FileOutputStream(fileOutput.getName());
        // Initialise le flux de sortie permettant d'ajouter des données à l'archive
        ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);
        // Parcourt l'ensemble des fichiers d'entrées
        for (int i = 0; i < inputFiles.size() + 1; i++) {
            InputStream inputStream;
            if (i < inputFiles.size()) {
                // Ajoute le fichier au flux de sortie (l'archive)
                zipOutputStream.putNextEntry(new ZipEntry(new File(inputFiles.get(i)).getName()));
                // Initialise le flux d'entrée correspondant aux octets de notre fichier chiffré ou déchiffré
                inputStream = new ByteArrayInputStream(filesData.get(i));
            } else {
                // Ajoute le fichier (contenant les IV et MAC) au flux de sortie (l'archive)
                zipOutputStream.putNextEntry(new ZipEntry(new File(RESERVED_NAME).getName()));
                // Initialise le flux d'entrée correspondant aux octets des IV et MAC
                inputStream = new ByteArrayInputStream(encryptData);
            }
            // Crée un buffer pour lire les octets du flux d'entrée
            byte[] bytes = new byte[1024];
            int length;
            // Transfert les octets du flux d'entrée vers l'archive
            while ((length = inputStream.read(bytes)) >= 0)
                zipOutputStream.write(bytes, 0, length);
            // Ferme le flux d'entrée
            inputStream.close();
        }
        // Ferme les flux de sortie
        zipOutputStream.close();
        fileOutputStream.close();
    }

    public static ArrayList<File> extractArchive(File inputFile) throws IOException {
        byte[] buffer = new byte[1024];
        ArrayList<File> files = new ArrayList<>();
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(inputFile));
        ZipEntry zipEntry = zipInputStream.getNextEntry();
        while(zipEntry != null) {
            File file = new File(zipEntry.getName());
            System.out.println(file.getName());
            FileOutputStream fos = new FileOutputStream(file);
            int length;
            while ((length = zipInputStream.read(buffer)) > 0)
                fos.write(buffer, 0, length);
            fos.close();
            files.add(file);
            zipEntry = zipInputStream.getNextEntry();
        }
        zipInputStream.closeEntry();
        zipInputStream.close();
        return files;
    }
}
