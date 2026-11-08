"""Copie le dossier de la boutique dans une archive zip datee."""
import shutil
import time


def sauvegarder(dossier, destination):
    """Cree destination/boutique-AAAAMMJJ.zip et renvoie son chemin."""
    nom = "boutique-" + time.strftime("%Y%m%d")
    return shutil.make_archive(destination + "/" + nom, "zip", dossier)
