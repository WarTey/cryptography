# Projet de cryptographie

Projet réalisé par Valentin Magnan et Guillaume Blanc de Lanaute.

## Compatibilité

Tout OS ayant java installé.

## Utilisation

Récupérer le fichier release-1.0-SNAPSHOT.jar dans le dossier release, ouvrez votre terminal préféré et saisissez la commande :
```bash
java -jar release-1.0-SNAPSHOT.jar -enc|-dec -key K..K -in <input file> -out <output file>
```
Un message d'aide s'affichera pour vous montrer à quoi correspondent les différents arguments et ainsi chiffrer ou déchiffrer vos données.
À noter que la clé secrète est au format hexadécimal donc seuls les chiffres et caractères de a/A à f/F sont autorisés.

## Contribution

Les 'Pull requests' sont les bienvenues. Pour les changements majeurs, veuillez d'abord ouvrir une 'Issue' pour discuter de ce que vous aimeriez changer.