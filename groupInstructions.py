import pandas as pd

def remove_duplicates(input_file, output_file):
    """
    Supprime les doublons d'un fichier CSV et sauvegarde le résultat dans un nouveau fichier.
    
    :param input_file: Chemin du fichier CSV d'entrée.
    :param output_file: Chemin du fichier CSV de sortie.
    """
    # Lire le fichier CSV
    df = pd.read_csv(input_file, delimiter='|')
    
    # Supprimer les doublons
    df.drop_duplicates(inplace=True)
    
    # Sauvegarder le résultat dans un nouveau fichier CSV
    df.to_csv(output_file, index=False, sep='|')
    
    print(f"Les doublons ont été supprimés. Le fichier résultant est sauvegardé sous '{output_file}'.")

# Exemple d'utilisation
if __name__ == "__main__":
    input_file = '4Bytes_processed.csv'  # Remplacez par le chemin de votre fichier CSV d'entrée
    output_file = '4Bytes_no_duplicates.csv'  # Remplacez par le chemin de votre fichier CSV de sortie
    remove_duplicates(input_file, output_file)