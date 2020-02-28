import java.io.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Scanner;
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
            // Erreur lors de la lecture de l'archive
            System.out.println("Attention, une erreur est survenue lors de la lecture de l'archive.");
        }
        // Retourne 'true' selon la signature du fichier
        return fileSignature == 0x504B0304 || fileSignature == 0x504B0506 || fileSignature == 0x504B0708;
    }

    // Vérifie l'ensemble des fichiers d'entrées et le fichier de sortie
    public static Boolean isInputFilesReady(ArrayList<String> inputFiles, String encryptionType) {
        // Pour le déchiffrement, vérifie que le fichier d'entrée est une archive
        if (encryptionType.equals("decryption") && !isArchive(new File(inputFiles.get(0)))) {
            // Affiche un message d'erreur et quitte le programme
            System.out.println("Attention, lors d'un déchiffrement, le paramètre d'entrée doit être une archive au format zip.");
            return false;
        }

        // Tableau permettant de contenir les noms de fichiers et ainsi éviter les doublons
        HashSet<String> duplicate = new HashSet<>();
        // Parcourt les fichiers d'entrées
        for (String inputFile : inputFiles) {
            // Initialise un des fichiers d'entrées
            File fileInput = new File(inputFile);
            // Vérifie que le fichier existe
            if (!fileInput.exists()) {
                // Le fichier n'existe pas
                System.out.println("Attention, un des fichiers d'entrées n'existe pas (" + fileInput.getName() + ").");
                return false;
            // Vérifie que le fichier ne soit pas un dossier
            } else if (!fileInput.isFile()) {
                // Le fichier est un dossier
                System.out.println("Attention, un des fichiers d'entrées est un dossier (" + fileInput.getName() + ").");
                return false;
            // Vérifie que le fichier ne soit pas un doublon
            } else if (duplicate.contains(fileInput.getName())) {
                // Le fichier est un doublon
                System.out.println("Attention, un des fichiers d'entrées est un doublon (" + fileInput.getName() + ").");
                return false;
            // Vérifie que le fichier ne possède pas un nom réservé
            } else if (fileInput.getName().equals(RESERVED_NAME)) {
                // Le fichier utilise un nom réservé
                System.out.println("Attention, un des fichiers d'entrées utilise un nom réservé (" + fileInput.getName() + ").");
                return false;
            // Rajoute le fichier au tableau 'des doublons'
            } else duplicate.add(fileInput.getName());
        }
        return true;
    }

    public static Boolean isOutputFilesReady(File fileOutput, String encryptionType) {
        // Pour le déchiffrement, vérifie que le dossier de sortie ne soit pas déjà présent
        if (encryptionType.equals("decryption") && fileOutput.isDirectory()) {
            // Affiche un message d'erreur et quitte le programme
            System.out.println("Attention, un dossier utilisant le nom " + fileOutput.getName() + " est déjà existant.");
            return false;
        } else if (encryptionType.equals("encryption")) {
            // Découpe le nom du fichier de sortie par rapport au '.'
            String[] splittedOutput = fileOutput.getName().split(Pattern.quote("."));
            // Vérifie que la dernière partie du nom soit 'zip'
            if (!splittedOutput[splittedOutput.length - 1].equals("zip")) {
                // Affiche un message d'erreur et quitte le programme
                System.out.println("Attention, lors d'un chiffrement, le paramètre de sortie doit être une archive au format zip.");
                return false;
            }
        }

        // Dans le cas où le fichier de sortie existe
        if (fileOutput.exists()) {
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
                if (!answer.equals("Y") || (!fileOutput.delete())) {
                    // Affiche un message d'erreur et quitte le programme
                    System.out.println("Processus interrompu.");
                    return false;
                }
            } else {
                // Affiche un message d'erreur et quitte le programme
                System.out.println("Attention, le fichier de sortie est un dossier.");
                return false;
            }
        }
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

    // Extrait l'archive contenant les fichiers chiffrés
    public static void extractArchive(String zipName, String outputFile) throws IOException {
        // Initialise le flux d'entrée permettant de récupérer des données de l'archive
        ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipName));
        // Représente les entrées d'une archive
        ZipEntry zipEntry = zipInputStream.getNextEntry();
        // Tant que l'archive contient une entrée
        while (zipEntry != null) {
            // Définit le chemin d'extraction
            String filePath = outputFile + File.separator + zipEntry.getName();
            // Vérifie que l'entrée soit différente d'un dossier
            if (!zipEntry.isDirectory()) {
                // Crée un nouveau flux de sortie pour écrire des données dans le flux de sortie spécifié
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(filePath));
                // Crée un buffer pour lire les octets de l'archive
                byte[] bytes = new byte[1024];
                int read;
                // Transfert les octets de l'archive vers le dossier
                while ((read = zipInputStream.read(bytes)) != -1)
                    bufferedOutputStream.write(bytes, 0, read);
                // Ferme le flux de sortie
                bufferedOutputStream.close();
            }
            // Ferme le flux de cette entrée
            zipInputStream.closeEntry();
            // Récupère l'entrée suivante
            zipEntry = zipInputStream.getNextEntry();
        }
        // Ferme le flux d'entrée
        zipInputStream.close();
    }

    // Récupère les noms des fichiers d'une archive
    public static ArrayList<String> extractNamesFromArchive(File inputFile) throws IOException {
        // Permet de lire les entrées d'une archive
        ZipFile zipFile = new ZipFile(inputFile.getPath());
        // Génère une série d'éléments correspondants aux entrées de l'archive
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        // Initialise un tableau contenant les noms des fichiers
        ArrayList<String> names = new ArrayList<>();
        // Itère autour de chaque entrée
        while (entries.hasMoreElements()) {
            // Récupère l'entrée suivante
            ZipEntry zipEntry = entries.nextElement();
            // Ajout le nom au tableau
            names.add(zipEntry.getName());
        }
        // Termine la lecture de l'archive
        zipFile.close();
        // Retourne les noms des fichiers
        return names;
    }
}
