public class FileIntegrityException extends Exception {

	private static final long serialVersionUID = -3604974696309735660L;

	public FileIntegrityException() {
		System.out.println("Fichier corrompu: Le MAC calculé ne correspond pas au MAC récupéré.");
	}
}
