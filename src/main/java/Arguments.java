import java.util.regex.Pattern;

public class Arguments {

    private static final String ERROR = "Error arguments";
    private static final String REGEX_KEY = "[0-9a-fA-F]{48}";

    public static String getEncryptionType(String[] args) {
        for (String arg : args) {
            if (arg.equals("-enc"))
                return "encryption";
            else if (arg.equals("-dec"))
                return "decryption";
        }
        return ERROR;
    }

    public static String getKey(String[] args) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals("-key"))
                if (args[i+1] != null && args[i+1].length() == 48 && Pattern.matches(REGEX_KEY, args[i+1]))
                    return args[i+1];
        return ERROR;
    }

    public static String getInputFile(String[] args) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals("-in"))
                if (args[i+1] != null && args[i+1].length() > 0)
                    return args[i+1];
        return ERROR;
    }

    public static String getOutputFile(String[] args) {
        for (int i = 0; i < args.length; i++)
            if (args[i].equals("-out"))
                if (args[i+1] != null && args[i+1].length() > 0)
                    return args[i+1];
        return ERROR;
    }
}
