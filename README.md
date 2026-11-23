# veille-cti

Bulletin de veille cybersécurité (CTI) quotidien, généré chaque matin à 6h35 (heure de Paris).

- Flux RSS : https://theophanelg.github.io/veille-cti/feed.xml
- Archive : https://theophanelg.github.io/veille-cti/

## Structure
- `data/AAAA-MM-JJ.json` : données du bulletin (seul fichier écrit chaque jour)
- `template.html` : mise en page des bulletins (ne pas modifier sans raison)
- `scripts/build.py` : génère `bulletins/*.html`, `bulletins/*.md` (notes Obsidian), `feed.xml` et `index.html`
