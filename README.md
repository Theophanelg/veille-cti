# veille-cti — Veille cybersécurité en français

Deux flux RSS pour suivre l'actualité cyber sans se noyer dans des dizaines de flux bruts :

| Flux | Rythme | Pour quoi faire | Adresse |
|---|---|---|---|
| **Bulletin CTI quotidien** | 1 fois par jour, vers 6h35 (heure de Paris) | Lire en 10-15 min ce qui compte depuis la veille, trié, expliqué et dédoublonné | `https://theophanelg.github.io/veille-cti/feed.xml` |
| **CVE critiques — alertes** | En continu (vérification toutes les 20 min) | Être prévenu dès qu'une faille critique apparaît ou est exploitée | `https://theophanelg.github.io/veille-cti/critique.xml` |

Les deux sont aussi consultables dans une interface web installable : **https://theophanelg.github.io/veille-cti/**

Contenu public, marqué **TLP:CLEAR** : il ne repose que sur des sources ouvertes et peut être partagé librement.

---

## 1. Le bulletin CTI quotidien (`feed.xml`)

### À quoi il sert
Remplacer la lecture de 10 flux RSS bruts par **un seul article par jour**, rédigé comme le bulletin du matin d'une équipe SOC / CERT / CTI (*daily threat intelligence brief*). Les informations sont regroupées par incident, les doublons fusionnés, et chaque sujet dit **ce qui s'est passé, comment, pourquoi c'est important et quoi faire**.

### Ce que contient chaque article
Le titre résume la journée : `🟠 Élevé · lun. 23 nov. — VMware vCenter, Apache Roller, F5 BIG-IP`.

1. **Niveau de menace du jour** : 🟢 Faible · 🟡 Modéré · 🟠 Élevé · 🔴 Critique, avec sa justification en une phrase.
2. **L'essentiel (BLUF, *Bottom Line Up Front*)** : 3 à 5 points, le plus urgent en premier, chacun avec l'action attendue.
3. **Vulnérabilités**, classées par priorité :
   - 🔴 **P1** : exploitée activement (CISA KEV, éditeur ou CERT) ou CVSS ≥ 9 avec PoC public sur un produit exposé à Internet ;
   - 🟠 **P2** : CVSS ≥ 7 ou EPSS ≥ 0,1, sans exploitation confirmée ;
   - ⚪ **P3** : le reste qui mérite d'être connu.

   Pour chaque faille : CVE, score **CVSS** (gravité), **EPSS** (probabilité d'exploitation sous 30 jours), présence au **KEV**, PoC public. Les P1 ont une fiche **Quoi ? / Comment ? / Pourquoi c'est important ?** et deux blocs **Détecter** (logs, artefacts, règles) et **Corriger** (version corrigée, contournement, échéance).
4. **Menaces & campagnes** : APT, ransomware, malware, phishing, avec attribution et **niveau de confiance**, et les techniques **MITRE ATT&CK** (liens vers attack.mitre.org).
5. **Ransomware — France** : victimes françaises revendiquées sur les sites de fuite, et groupes les plus actifs de la période.
6. **Fuites de données** : France d'abord, puis international (dont les ajouts Have I Been Pwned).
7. **IOC** notables, toujours **défangés** (`hxxp://`, `exemple[.]com`) pour éviter tout clic accidentel.
8. **Réglementaire & institutionnel** : ANSSI, CNIL, NIS2, sanctions, démantèlements.
9. **À creuser** : un sujet technique du jour avec une piste de lab **légal** (VM locale isolée, HackTheBox, TryHackMe).

### Sources consultées
BleepingComputer · The Hacker News · The Record · SecurityWeek · ZATAZ · LeMagIT · Next · CERT-FR (alertes, avis, CTI, IOC) · CISA KEV · NVD · FIRST EPSS · ransomware.live · Have I Been Pwned · Bonjour La Fuite · SANS Internet Storm Center.

### Règles de rédaction
- Aucun chiffre, CVE, score ou attribution inventé : une donnée introuvable est notée `N/A`.
- Une fuite revendiquée mais non confirmée est marquée **« Non vérifiée »** ; une info rapportée par une seule source, **« (non confirmé) »**.
- Pas de marketing, de « top 10 », d'articles sponsorisés ni de levées de fonds.
- Chaque information renvoie vers son article source.
- Les sources indisponibles ce jour-là sont listées en bas de l'article.

---

## 2. Les alertes CVE critiques (`critique.xml`)

### À quoi il sert
Ne pas attendre le bulletin du lendemain quand une faille majeure sort, du type *React2Shell*, *Log4Shell* ou un zero-day Fortinet/Ivanti. Un robot (GitHub Actions, sans IA) vérifie les sources **toutes les 20 minutes** et publie **une alerte par CVE**, uniquement quand elle mérite une attention immédiate.

### Ce qui déclenche une alerte
| Badge | Déclencheur |
|---|---|
| 🚨 **KEV** | La CVE vient d'être ajoutée au catalogue **CISA Known Exploited Vulnerabilities** : exploitation active confirmée. |
| 🇫🇷 **CERT-FR** | Le CERT-FR (ANSSI) publie une nouvelle **alerte** (`CERTFR-AAAA-ALE-NNN`), réservée aux menaces critiques. |
| 🚨 **NVD** | Nouvelle CVE **CVSS ≥ 9**, exploitable **par le réseau sans authentification**, sur un produit de la [liste de surveillance](critique/watchlist.txt). |

Les plugins et thèmes WordPress, Joomla ou Drupal sont exclus (des dizaines de 9,8 par jour), sauf s'ils entrent au KEV. Une CVE déjà signalée qui entre ensuite au KEV produit une **nouvelle alerte** : c'est une aggravation.

### Ce que contient chaque alerte
Titre : `🚨 CVE-2026-76466 — Cisco Expressway Series · KEV · CVSS 9,8`

- la raison de l'alerte ;
- CVE (lien NVD), CVSS et version, EPSS et percentile, date d'ajout au KEV ;
- le vecteur CVSS complet ;
- la description officielle (en anglais, telle que publiée par la NVD) ;
- pour le KEV : action exigée par la CISA, échéance fédérale, usage connu par des ransomwares ;
- les produits concernés (CPE) et les liens de référence (éditeur, avis, PoC).

### Ajuster le filtre
Modifier [`critique/watchlist.txt`](critique/watchlist.txt) : un éditeur ou produit par ligne. Le robot relit la liste à chaque passage.

---

## 3. S'abonner et lire

| Où | Comment |
|---|---|
| **NetNewsWire** (iPhone, iPad, Mac) | *Fichier → Nouveau flux* (ou **+**), coller l'adresse du flux. |
| **Feedly, Inoreader** (Windows, Linux, Android, web) | Ajouter un flux, coller l'adresse. La lecture est synchronisée entre appareils. |
| **Obsidian** | Plugin RSS (*RSS Reader*, *RSS Dashboard*…) avec l'adresse du flux, ou plugin *Obsidian Git* pour récupérer les notes Markdown de [`bulletins/`](bulletins/) : une note par jour avec métadonnées (`date`, `niveau`, `cves`) et callouts colorés. |
| **Interface web** | https://theophanelg.github.io/veille-cti/ : onglets *Bulletins* (par semaine, recherche, filtres) et *CVE critiques* (alertes en direct). |
| **Comme une application** | iPhone : Safari → Partager → *Sur l'écran d'accueil*. Android : Chrome → *Installer l'application*. PC : Chrome ou Edge → icône d'installation dans la barre d'adresse. |

Chaque bulletin a aussi une adresse directe : `…/veille-cti/#2026-11-23`, et chaque alerte : `…/veille-cti/#c-KEV-CVE-2026-76466`.

---

## 4. Fonctionnement technique

```
Chaque matin (6h35)                         Toutes les 20 min (GitHub Actions)
  tâche planifiée Claude                      scripts/critique.py
  → collecte + analyse des sources            → CISA KEV, NVD, EPSS, CERT-FR
  → écrit data/AAAA-MM-JJ.json                → critique/items.json
  → scripts/build.py                          → critique.xml
      bulletins/<date>.html  (page)
      bulletins/<date>.md    (note Obsidian)
      feed.xml, index.html, latest.html
                    ↓
            GitHub Pages (publication)
```

| Fichier | Rôle |
|---|---|
| `data/*.json` | Données de chaque bulletin (seul fichier écrit chaque matin) |
| `scripts/exemple.json` | Exemple de référence du format des données |
| `template.html` | Mise en page d'un bulletin |
| `scripts/build.py` | Génère pages, notes Obsidian, flux RSS et interface (Python, bibliothèque standard uniquement) |
| `scripts/index_template.html` | Interface de lecture |
| `scripts/critique.py`, `.github/workflows/critique.yml` | Robot des alertes CVE critiques |
| `critique/watchlist.txt` | Produits surveillés par le robot |

Régénérer le site en local : `python3 scripts/build.py`

---

## Avertissement
Bulletin produit automatiquement à partir de sources publiques, à des fins de veille et d'apprentissage. Il peut contenir des erreurs ou des omissions : vérifier les informations auprès des sources citées (éditeurs, CERT-FR, CISA) avant toute décision opérationnelle. Les pistes de lab ne visent que des environnements autorisés.
