import java.io.*;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class FileManager {

    // Vérifie l'ensemble des fichiers d'entrées
    public static Boolean isInputFilesReady(ArrayList<String> inputFiles, String outputFile) {
        // Parcourt les fichiers d'entrées
        for (String inputFile : inputFiles) {
            // Initialise un des fichiers d'entrées
            File fileInput = new File(inputFile);
            // Vérifie que le fichier existe, ne soit pas un dossier et qu'il soit différent du fichier de sortie
            if (!fileInput.exists() || !fileInput.isFile() || inputFile.equals(outputFile))
                // Le fichier n'est pas correct
                return false;
        }
        // Les fichiers sont corrects
        return true;
    }

    public static void createArchive(ArrayList<String> inputFiles, ArrayList<byte[]> filesData, File fileOutput) throws IOException {
        // Initialise le flux de sortie permettant d'écrire dans le fichier
        FileOutputStream fileOutputStream = new FileOutputStream(fileOutput.getName());
        // Initialise le flux de sortie permettant d'ajouter des données à l'archive
        ZipOutputStream zipOutputStream = new ZipOutputStream(fileOutputStream);
        // Parcourt l'ensemble des fichiers d'entrées
        for (int i = 0; i < inputFiles.size(); i++) {
            // Ajoute le fichier au flux de sortie (l'archive)
            zipOutputStream.putNextEntry(new ZipEntry(new File(inputFiles.get(i)).getName()));
            // Initialise le flux d'entrée correspondant aux octets de notre fichier chiffré ou déchiffré
            InputStream inputStream = new ByteArrayInputStream(filesData.get(i));
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
}
