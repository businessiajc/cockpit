"""Genere le texte d'une fiche produit a partir d'une entree du catalogue."""


def titre(bougie):
    """Construit le titre de la fiche, par exemple 'Bougie Lavande - 180 g'."""
    return "Bougie %s - %d g" % (bougie["nom"], bougie["poids"])


def fiche(bougie):
    """Assemble la fiche complete : titre, parfum, duree de combustion."""
    lignes = [titre(bougie), "Parfum : " + bougie["parfum"],
              "Duree de combustion : %d heures" % bougie["heures"]]
    return "\n".join(lignes)


def tout_generer(catalogue):
    """Genere les fiches de toutes les bougies et les renvoie dans une liste."""
    return [fiche(b) for b in catalogue["bougies"]]
