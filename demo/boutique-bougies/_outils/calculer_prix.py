"""Calcul du prix de vente d'une bougie a partir de son cout de fabrication."""
import json


def prix_de_vente(cout, marge=0.5):
    """Renvoie le prix de vente qui garantit la marge voulue (par defaut 50 %)."""
    if not 0 <= marge < 1:
        raise ValueError("La marge doit etre comprise entre 0 et 1.")
    return round(cout / (1 - marge), 2)


def verifier_catalogue(chemin):
    """Liste les bougies dont le prix est trop bas pour la marge minimale."""
    with open(chemin, encoding="utf-8") as f:
        catalogue = json.load(f)
    trop_bas = []
    for b in catalogue["bougies"]:
        if b["prix"] < prix_de_vente(b["cout"], 0.4):
            trop_bas.append(b["nom"])
    return trop_bas


if __name__ == "__main__":
    print(prix_de_vente(4.0))
