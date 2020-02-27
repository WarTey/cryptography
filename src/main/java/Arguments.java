import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;

public class Arguments {

    // Regex pour vérifier la clé
    private static final String REGEX_KEY = "[0-9a-fA-F]{48}";
    // Paramètres des arguments
    private static final String[] PARAMETERS = {"-enc", "-dec", "-key", "-in", "-out"};

    // Récupère le type de chiffrement
    public static String getEncryptionType(String[] args) {
        // On parcourt tous les arguments
        for (String arg : args) {
            // On vérifie si cet argument correspond au chiffrement et renvoie le type
            if (arg.equals(PARAMETERS[0]))
                return "encryption";
            // On vérifie si cet argument correspond au déchiffrement et renvoie le type
            else if (arg.equals(PARAMETERS[1]))
                return "decryption";
        }
        // Renvoie null si rien
        return null;
    }

    public static String getKey(String[] args) {
        // On parcourt tous les arguments
        for (int i = 0; i < args.length; i++)
            // On vérifie si cet argument correspond à la clé
            if (args[i].equals(PARAMETERS[2]))
                // Vérifie si l'argument suivant (qui est la clé) existe, possède la bonne taille et passe le regex
                if (args[i+1] != null && args[i+1].length() == 48 && Pattern.matches(REGEX_KEY, args[i+1]))
                    // Retourne la clé
                    return args[i+1];
        // Renvoie null si rien
        return null;
    }

    public static String getOutputFile(String[] args) {
        // On parcourt tous les arguments
        for (int i = 0; i < args.length; i++)
            // On vérifie si cet argument correspond au fichier de sortie
            if (args[i].equals(PARAMETERS[4]))
                // Vérifie si l'argument suivant existe et renvoie sa valeur
                if (args[i + 1] != null && args[i + 1].length() > 0)
                    return args[i + 1];
        // Renvoie null si rien
        return null;
    }

    public static ArrayList<String> getInputFile(String[] args) {
        // Initialise le tableau contenant les noms des fichiers à chiffrer
        ArrayList<String> inputs = new ArrayList<>();
        // On parcourt tous les arguments
        for (int i = 0; i < args.length; i++)
            // On vérifie si cet argument correspond au fichier d'entrée
            if (args[i].equals(PARAMETERS[3]))
                // Parcourt les arguments qui suivent
                for (int j = i+1; j < args.length; j++) {
                    // Vérifie si l'argument suivant existe, s'il ne s'agit pas d'un paramètre et sauvegarde sa valeur
                    if (args[j] != null && args[j].length() > 0 && !Arrays.asList(PARAMETERS).contains(args[j]))
                        inputs.add(args[j]);
                        // Dans le cas où l'argument qui suit est un paramètre renvoie null
                    else return inputs;
                }
        // Renvoie null si rien
        return null;
    }

    // Renvoie l'aide pour les arguments
    public static String helpArguments () {
        String space = "    ";
        // Exemple d'usage: filecrypt -enc|-dec -key K..K -in <input file> -out <output file>
        String errorMessage = "\nExample usage:\n";
        errorMessage += space + "java -jar release-X.jar -enc|-dec -key K..K -in <input file> -out <output file>\n\n";
        // Description des arguments (à quoi ils correspondent)
        errorMessage += "Arguments:\n";
        errorMessage += space + "-enc: encryption\n";
        errorMessage += space + "-dec: decryption\n";
        errorMessage += space + "-key: secret key (48 characters)\n";
        errorMessage += space + "-in: input files\n";
        errorMessage += space + "-out: output file (different from the input file)\n\n";
        // Plus d'informations
        errorMessage += "With encryption mode, you can send multiples files but with decryption mode, ony the ciphered archive is necessary.\n";
        // Renvoie le message d'aide
        return errorMessage;
    }
}
