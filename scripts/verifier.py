#!/usr/bin/env python3
"""Garde-fou exécuté par la tâche du matin juste avant `git commit`.

Refuse la publication si des fichiers autres que ceux d'un bulletin ont été modifiés
(protection contre une tâche manipulée par un contenu piégé : injection de prompt).
Usage : git add -A && python3 scripts/verifier.py
"""
import re
import subprocess
import sys

AUTORISES = re.compile(r"^(data/\d{4}-\d{2}-\d{2}(-\d{4})?\.json|bulletins/\d{4}-\d{2}-\d{2}(-\d{4})?\.(html|md)|feed\.xml|index\.html|latest\.html)$")

out = subprocess.run(["git", "diff", "--cached", "--name-status"], capture_output=True, text=True, check=True).stdout
refus = []
for line in out.splitlines():
    status, *paths = line.split("\t")
    for p in paths:
        if not AUTORISES.match(p):
            refus.append(f"{status} {p}")
        elif status.startswith("D") and p.startswith("data/"):
            refus.append(f"{status} {p} (suppression d'un bulletin)")

if refus:
    print("PUBLICATION REFUSÉE : la tâche ne doit modifier que le bulletin du jour.\n- " + "\n- ".join(refus))
    print("Annule ces changements (git restore --staged <fichier> && git checkout -- <fichier>) puis recommence.")
    sys.exit(1)
print("Vérification OK :", ", ".join(l.split("\t")[-1] for l in out.splitlines()) or "aucun changement")
