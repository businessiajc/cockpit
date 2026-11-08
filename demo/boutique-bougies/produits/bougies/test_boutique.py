"""Tests de la boutique : verifie le calcul des prix."""
import sys
sys.path.insert(0, "../../_outils")
from calculer_prix import prix_de_vente


def test_marge():
    """Un cout de 4 euros avec 50 % de marge donne un prix de 8 euros."""
    assert prix_de_vente(4.0) == 8.0
