import java.util.regex.Pattern;

public class Arguments {

    // Regex pour vérifier la clé
    private static final String REGEX_KEY = "[0-9a-fA-F]{48}";

    // Récupère le type de chiffrement
    public static String getEncryptionType(String[] args) {
        // On parcourt tous les arguments
        for (String arg : args) {
            // On vérifie si cette argument correspond au chiffrement et renvoie le type
            if (arg.equals("-enc"))
                return "encryption";
            // On vérifie si cette argument correspond au déchiffrement et renvoie le type
            else if (arg.equals("-dec"))
                return "decryption";
        }
        // Renvoie null si rien
        return null;
    }

    public static String getKey(String[] args) {
        // On parcourt tous les arguments
        for (int i = 0; i < args.length; i++)
            // On vérifie si cette argument correspond à la clé
            if (args[i].equals("-key"))
                // Vérifie si l'argument suivant (qui est la clé) existe, possède la bonne taille et passe le regex
                if (args[i+1] != null && args[i+1].length() == 48 && Pattern.matches(REGEX_KEY, args[i+1]))
                    // Retourne la clé
                    return args[i+1];
        // Renvoie null si rien
        return null;
    }

    public static String getFile(String[] args, Boolean isInputFile) {
        // On parcourt tous les arguments
        for (int i = 0; i < args.length; i++)
            // On vérifie si cette argument correspond au fichier d'entrée ou de sortie
            if ((isInputFile && args[i].equals("-in")) || (!isInputFile && args[i].equals("-out")))
                // Vérifie le l'argument suivant existe et renvoie sa valeur
                if (args[i+1] != null && args[i+1].length() > 0)
                    return args[i+1];
        // Renvoie null si rien
        return null;
    }
}
