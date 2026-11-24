#!/usr/bin/env python3
"""Collecte des sources du bulletin CTI (exécutée par GitHub Actions avant la tâche du matin).

Fenêtre : de 06:35 la veille (le lundi : vendredi 06:35) jusqu'à maintenant, heure de Paris.
Sortie : raw/AAAA-MM-JJ.json (date de Paris du jour), lu par la tâche planifiée qui rédige le bulletin.
On ne conserve que des métadonnées et des extraits courts (≤ 600 caractères), jamais le texte intégral des articles.
Bibliothèque standard uniquement.
"""
import datetime as dt
import html
import json
import pathlib
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

ROOT = pathlib.Path(__file__).resolve().parent.parent
PARIS = ZoneInfo("Europe/Paris")
UA = {"User-Agent": "Mozilla/5.0 (veille-cti; +https://github.com/Theophanelg/veille-cti)"}
NOW = dt.datetime.now(PARIS).replace(microsecond=0)
EXCERPT = 600

FEEDS = {
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "The Record": "https://therecord.media/feed/",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "ZATAZ": "https://www.zataz.com/feed/",
    "SANS ISC": "https://isc.sans.edu/rssfeed_full.xml",
    "HIBP": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches",
    "LeMagIT": "https://www.lemagit.fr/rss/Securite.xml",
    "Next": "https://next.ink/feed/",
    "CERT-FR (flux)": "https://cert.cyber.gouv.fr/feed/",
}
CERT_PAGES = ["alerte", "avis", "actualite", "cti", "ioc"]
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def window_start():
    today = NOW.date()
    back = 3 if today.weekday() == 0 else 1  # lundi : depuis vendredi
    return dt.datetime.combine(today - dt.timedelta(days=back), dt.time(6, 35), PARIS)


START = window_start()


def get(url, as_json=False, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
                raw = r.read().decode("utf-8", "replace")
                return (json.loads(raw) if as_json else raw), None
        except Exception as ex:  # noqa: BLE001
            err = str(ex)
            time.sleep(5 * (i + 1))
    return None, err


def clean(s, n=EXCERPT):
    s = re.sub(r"<[^>]+>", " ", html.unescape(s or ""))
    s = re.sub(r"\s+", " ", html.unescape(s)).strip()
    return s if len(s) <= n else s[: n - 1].rsplit(" ", 1)[0] + "…"


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except Exception:  # noqa: BLE001
        try:
            d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.astimezone(PARIS)


def feed(name, url):
    text, err = get(url)
    if text is None:
        return {"ok": False, "erreur": err, "items": []}
    try:
        root = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as ex:
        return {"ok": False, "erreur": f"XML invalide : {ex}", "items": []}
    ns = {"a": "http://www.w3.org/2005/Atom", "dc": "http://purl.org/dc/elements/1.1/"}
    items, newest = [], None
    for it in root.iter("item"):
        d = parse_date(it.findtext("pubDate") or it.findtext("dc:date", namespaces=ns))
        newest = max(newest, d) if newest and d else (d or newest)
        if d and d < START:
            continue
        desc = it.findtext("description") or ""
        items.append({"titre": clean(it.findtext("title"), 300), "url": (it.findtext("link") or "").strip(),
                      "date": d.isoformat() if d else None, "extrait": clean(desc),
                      "categories": [clean(c.text, 60) for c in it.findall("category") if c.text][:6]})
    for it in root.iter("{http://www.w3.org/2005/Atom}entry"):
        d = parse_date(it.findtext("a:updated", namespaces=ns) or it.findtext("a:published", namespaces=ns))
        newest = max(newest, d) if newest and d else (d or newest)
        if d and d < START:
            continue
        link = it.find("a:link", ns)
        items.append({"titre": clean(it.findtext("a:title", namespaces=ns), 300), "url": link.get("href") if link is not None else "",
                      "date": d.isoformat() if d else None, "extrait": clean(it.findtext("a:summary", namespaces=ns) or it.findtext("a:content", namespaces=ns))})
    out = {"ok": True, "items": items, "dernier_article": newest.isoformat() if newest else None}
    if newest and newest < START:
        out["remarque"] = "flux figé : aucun article dans la fenêtre"
    return out


def certfr():
    res = {}
    for page in CERT_PAGES:
        text, err = get(f"https://cert.cyber.gouv.fr/{page}/")
        if text is None:
            res[page] = {"ok": False, "erreur": err, "items": []}
            continue
        seen, items = set(), []
        for m in re.finditer(r'href="([^"]*?(CERTFR-\d{4}-[A-Z]{3}-\d{3,4})[^"]*)"[^>]*>(.*?)</a>', text, re.S):
            url, ref, label = m.group(1), m.group(2), clean(m.group(3), 200)
            if ref in seen:
                continue
            seen.add(ref)
            ctx = clean(text[m.end(): m.end() + 600], 400)
            date = re.search(r"\b(\d{1,2} (?:janvier|février|mars|avril|mai|juin|juillet|août|septembre|octobre|novembre|décembre) \d{4}|\d{2}/\d{2}/\d{4})\b", ctx)
            items.append({"ref": ref, "titre": label if label and label != ref else "", "url": ("https://cert.cyber.gouv.fr" + url) if url.startswith("/") else url,
                          "date": date.group(1) if date else None})
            if len(items) >= 15:
                break
        res[page] = {"ok": True, "items": items}
    return res


def kev():
    data, err = get(KEV_URL, as_json=True)
    if data is None:
        return {"ok": False, "erreur": err, "items": []}
    floor = START.date().isoformat()
    keep = ["cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse"]
    return {"ok": True, "catalogue_du": data.get("dateReleased"),
            "items": [{k: v.get(k) for k in keep} for v in data.get("vulnerabilities", []) if v.get("dateAdded", "") >= floor]}


def ransomware():
    res = {}
    for key, url in {"france": "https://api.ransomware.live/v2/countryvictims/FR", "global": "https://api.ransomware.live/v2/recentvictims"}.items():
        data, err = get(url, as_json=True)
        if data is None:
            res[key] = {"ok": False, "erreur": err, "items": []}
            continue
        rows = data if isinstance(data, list) else data.get("victims") or data.get("data") or []
        items = []
        for v in rows:
            d = None
            for f in ("discovered", "attackdate", "published", "date"):
                d = parse_date(str(v.get(f) or "").replace(" ", "T")) or d
                if d:
                    break
            if d and d < START - dt.timedelta(days=1):
                continue
            items.append({"victime": v.get("victim") or v.get("post_title") or v.get("name"), "groupe": v.get("group") or v.get("group_name"),
                          "pays": v.get("country"), "secteur": v.get("activity") or v.get("sector"), "date": d.isoformat() if d else None,
                          "site": v.get("website") or v.get("domain"), "description": clean(v.get("description") or "", 300)})
        groups = {}
        for i in items:
            if i["groupe"]:
                groups[i["groupe"]] = groups.get(i["groupe"], 0) + 1
        res[key] = {"ok": True, "items": items[:80] if key == "global" else items, "total": len(items),
                    "groupes": sorted(groups.items(), key=lambda x: -x[1])[:8]}
    return res


def bonjourlafuite():
    text, err = get("https://bonjourlafuite.eu.org/")
    if text is None:
        return {"ok": False, "erreur": err, "items": []}
    items = []
    for m in re.finditer(r"<h2[^>]*>(.*?)</h2>(.*?)(?=<h2|$)", text, re.S):
        titre, body = clean(m.group(1), 150), m.group(2)
        date = re.search(r"\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2}|\d{1,2} \w+ \d{4}", clean(body, 400))
        links = re.findall(r'href="(https?://[^"]+)"', body)[:2]
        items.append({"titre": titre, "date": date.group(0) if date else None, "extrait": clean(body, 300), "liens": links})
        if len(items) >= 12:
            break
    return {"ok": True, "items": items, "remarque": "les 12 entrées les plus récentes de la page, sans filtre de date"}


def enrich(cves):
    out, epss = {}, {}
    for i in range(0, len(cves), 80):
        data, _ = get(f"https://api.first.org/data/v1/epss?cve={','.join(cves[i:i + 80])}", as_json=True)
        for r in (data or {}).get("data", []):
            epss[r["cve"]] = {"epss": float(r["epss"]), "percentile": float(r["percentile"])}
    for cid in cves[:40]:
        data, err = get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}", as_json=True)
        time.sleep(6.5)
        rec = {"epss": epss.get(cid)}
        for item in (data or {}).get("vulnerabilities", []):
            c = item["cve"]
            best = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                for m in c.get("metrics", {}).get(key, []):
                    d = m.get("cvssData", {})
                    if d.get("baseScore") is not None and (best is None or d["baseScore"] > best["score"]):
                        best = {"score": d["baseScore"], "version": d.get("version"), "vecteur": d.get("vectorString"), "source": m.get("source")}
            rec.update({"cvss": best, "publiee": c.get("published"), "statut_nvd": c.get("vulnStatus"),
                        "description": clean(next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), ""), 500),
                        "cwe": sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")})})
        if data is None:
            rec["erreur_nvd"] = err
        out[cid] = rec
    return out


def main():
    raw = {"genere_le": NOW.isoformat(), "fenetre": {"debut": START.isoformat(), "fin": NOW.isoformat()},
           "avertissement": "Extraits courts et métadonnées uniquement. Ouvrir l'URL de l'article pour le détail.",
           "flux": {n: feed(n, u) for n, u in FEEDS.items()}, "certfr": certfr(), "kev": kev(),
           "ransomware": ransomware(), "bonjourlafuite": bonjourlafuite()}
    text = json.dumps({k: raw[k] for k in ("flux", "certfr", "bonjourlafuite")}, ensure_ascii=False)
    cves = sorted(set(CVE_RE.findall(text)) | {k["cveID"] for k in raw["kev"]["items"]})
    raw["cve"] = enrich(cves)
    out = ROOT / "raw" / f"{NOW.date().isoformat()}.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(raw, ensure_ascii=False, indent=1), encoding="utf-8")
    for old in sorted((ROOT / "raw").glob("????-??-??.json"))[:-14]:
        old.unlink()  # on ne garde que 14 jours
    n = sum(len(f["items"]) for f in raw["flux"].values())
    ko = [n_ for n_, f in raw["flux"].items() if not f["ok"]] + [p for p, f in raw["certfr"].items() if not f["ok"]]
    print(f"{out.name} : {n} articles, {len(raw['kev']['items'])} KEV, {len(cves)} CVE, sources en échec : {ko or 'aucune'}")


if __name__ == "__main__":
    main()
