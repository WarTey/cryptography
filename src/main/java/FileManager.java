import java.io.File;
import java.util.ArrayList;

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
}
