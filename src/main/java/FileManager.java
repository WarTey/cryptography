import java.io.*;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
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
            System.out.println("Attention, une erreur est survenue lors de la lecture de l'archive.");
        }
        // Retourne 'true' selon la signature du fichier
        return fileSignature == 0x504B0304 || fileSignature == 0x504B0506 || fileSignature == 0x504B0708;
    }

    // Vérifie l'ensemble des fichiers d'entrées
    public static Boolean isInputFilesReady(ArrayList<String> inputFiles, File fileOutput, String encryptionType) {
        // Détermine si le fichier est une archive pour le déchiffrement
        if (encryptionType.equals("decryption")) {
            if (!isArchive(new File(inputFiles.get(0)))) {
                // Affiche un message d'erreur et quitte le programme
                System.out.println("Attention, lors d'un déchiffrement, le paramètre d'entrée doit être une archive au format zip.");
                return false;
            } else if (fileOutput.isDirectory()) {
                System.out.println("Attention, un dossier utilisant le nom " + fileOutput.getName() + " est déjà présent. Veuillez le supprimer.");
                return false;
            }
        } else if (encryptionType.equals("encryption")) {
            String[] splittedOutput = fileOutput.getName().split(Pattern.quote("."));
            if (!splittedOutput[splittedOutput.length - 1].equals("zip")) {
                // Affiche un message d'erreur et quitte le programme
                System.out.println("Attention, lors d'un chiffrement, le paramètre de sortie doit être une archive au format zip.");
                return false;
            }
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
            InputStream inputStream = null;
            if (i < inputFiles.size()) {
                // Ajoute le fichier au flux de sortie (l'archive)
                zipOutputStream.putNextEntry(new ZipEntry(new File(inputFiles.get(i)).getName()));
                // Initialise le flux d'entrée correspondant aux octets de notre fichier chiffré ou déchiffré
                inputStream = new ByteArrayInputStream(filesData.get(i));
            } else if (encryptData != null) {
                // Ajoute le fichier (contenant les IV et MAC) au flux de sortie (l'archive)
                zipOutputStream.putNextEntry(new ZipEntry(new File(RESERVED_NAME).getName()));
                // Initialise le flux d'entrée correspondant aux octets des IV et MAC
                inputStream = new ByteArrayInputStream(encryptData);
            }

            if (inputStream != null) {
                // Crée un buffer pour lire les octets du flux d'entrée
                byte[] bytes = new byte[1024];
                int length;
                // Transfert les octets du flux d'entrée vers l'archive
                while ((length = inputStream.read(bytes)) >= 0)
                    zipOutputStream.write(bytes, 0, length);
                // Ferme le flux d'entrée
                inputStream.close();
            }
        }
        // Ferme les flux de sortie
        zipOutputStream.close();
        fileOutputStream.close();
    }

    public static void extractArchive(String zipName, String outputFile) throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipName));
        ZipEntry zipEntry = zipInputStream.getNextEntry();
        while (zipEntry != null) {
            String filePath = outputFile + File.separator + zipEntry.getName();
            if (!zipEntry.isDirectory()) {
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
                byte[] bytes = new byte[1024];
                int read;
                while ((read = zipInputStream.read(bytes)) != -1)
                    bos.write(bytes, 0, read);
                bos.close();
            }
            zipInputStream.closeEntry();
            zipEntry = zipInputStream.getNextEntry();
        }
        zipInputStream.close();
    }

    public static ArrayList<String> extractNamesFromArchive(File inputFile) throws IOException {
        ZipFile zipFile = new ZipFile(inputFile.getPath());
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        ArrayList<String> names = new ArrayList<>();
        while (entries.hasMoreElements()) {
            ZipEntry zipEntry = entries.nextElement();
            names.add(zipEntry.getName());
        }
        zipFile.close();
        return names;
    }
}
