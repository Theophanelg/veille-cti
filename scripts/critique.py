#!/usr/bin/env python3
"""Flux « CVE critiques » quasi temps réel (exécuté par GitHub Actions toutes les 20 min).

Déclencheurs :
  1. nouvel ajout au CISA KEV (exploitation active) ;
  2. nouvelle alerte CERT-FR (CERTFR-AAAA-ALE-NNN) ;
  3. nouvelle CVE CVSS >= 9, AV:N et PR:N, sur un produit de critique/watchlist.txt.
Sorties : critique/items.json (60 dernières alertes), critique/state.json, critique.xml.
Aucune dépendance externe (stdlib uniquement).
"""
import datetime as dt
import html
import json
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request
from email.utils import format_datetime

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIR = ROOT / "critique"
STATE, ITEMS = DIR / "state.json", DIR / "items.json"
BASE = "https://theophanelg.github.io/veille-cti/"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
CERT_URL = "https://cert.cyber.gouv.fr/alerte/"
UA = {"User-Agent": "veille-cti/1.0 (+https://github.com/Theophanelg/veille-cti)"}
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
LOG = []


def get(url, as_json=True, tries=3):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40) as r:
                raw = r.read().decode("utf-8", "replace")
                return json.loads(raw) if as_json else raw
        except Exception as ex:  # noqa: BLE001
            if i == tries - 1:
                LOG.append(f"échec {url.split('?')[0]} : {ex}")
                return None
            time.sleep(6 * (i + 1))


def load(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return default


def watchlist():
    words = []
    for line in (DIR / "watchlist.txt").read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            words.append(line)
    return words


NOISE = re.compile(r"(plugin|theme|add-on|extension) for (wordpress|joomla|drupal)|wordpress (plugin|theme)|joomla (component|extension)|drupal module", re.I)


def guess_product(desc):
    """Déduit le produit de la description NVD quand les CPE ne sont pas encore renseignés."""
    hits = re.findall(r"\bin (?:the )?([A-Z][\w.\-]*(?: [A-Z(][\w.\-()]*){0,5}?)(?: v?\d[\w.\-]*)? (?:before|through|prior to|versions?|up to|<=|from)\b", desc)
    return hits[-1].strip() if hits else ""


def match_watch(text, words):
    t = text.lower()
    for w in words:
        if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", t):
            return w
    return None


# ---------- sources ----------
def from_kev(since, seen):
    data = get(KEV_URL)
    if not data:
        return {}, set()
    out, all_ids = {}, set()
    floor = (since - dt.timedelta(days=2)).date().isoformat()
    for v in data.get("vulnerabilities", []):
        cid = v["cveID"]
        all_ids.add(cid)
        if f"KEV:{cid}" in seen or v.get("dateAdded", "") < floor:
            continue
        out[cid] = {"kev": v}
    return out, all_ids


def nvd_metrics(cve):
    best = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in cve.get("metrics", {}).get(key, []):
            d = m.get("cvssData", {})
            cand = {"score": d.get("baseScore"), "vector": d.get("vectorString", ""), "version": d.get("version", ""),
                    "source": m.get("source", ""), "primary": m.get("type") == "Primary"}
            if cand["score"] is None:
                continue
            if best is None or cand["score"] > best["score"] or (cand["primary"] and not best["primary"] and cand["score"] >= best["score"]):
                best = cand
    return best


def nvd_products(cve):
    prods = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5 and m.get("vulnerable"):
                    vp = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if vp not in prods:
                        prods.append(vp)
    return prods


def from_nvd(since):
    out = {}
    start = (since - dt.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end = NOW.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    for sev in ("cvssV3Severity", "cvssV4Severity"):
        q = urllib.parse.urlencode({"lastModStartDate": start, "lastModEndDate": end, sev: "CRITICAL", "resultsPerPage": 2000})
        data = get(f"{NVD_URL}?{q}")
        time.sleep(7)  # limite NVD sans clé : 5 requêtes / 30 s
        for item in (data or {}).get("vulnerabilities", []):
            c = item["cve"]
            out[c["id"]] = c
    return out


def from_certfr(seen):
    page = get(CERT_URL, as_json=False)
    if not page:
        return []
    found, ids = [], set()
    for m in re.finditer(r'href="([^"]*?(CERTFR-\d{4}-ALE-\d{3,4})[^"]*)"[^>]*>(.*?)</a>', page, re.S):
        url, ref, label = m.group(1), m.group(2), re.sub(r"<[^>]+>", " ", m.group(3))
        label = re.sub(r"\s+", " ", html.unescape(label)).strip()
        if ref in ids:
            continue
        ids.add(ref)
        if f"ALE:{ref}" in seen:
            continue
        if url.startswith("/"):
            url = "https://cert.cyber.gouv.fr" + url
        found.append({"ref": ref, "url": url, "titre": label if label and label != ref else ref})
    return found


def epss(cves):
    res = {}
    for i in range(0, len(cves), 80):
        data = get(f"{EPSS_URL}?cve={','.join(cves[i:i + 80])}")
        for r in (data or {}).get("data", []):
            res[r["cve"]] = (float(r["epss"]), float(r["percentile"]))
    return res


# ---------- construction des alertes ----------
def fr_num(x, nd=1):
    return f"{x:.{nd}f}".replace(".", ",")


def build_cve_item(cid, nvd, kev, ep, why, watch):
    desc = next((d["value"] for d in (nvd or {}).get("descriptions", []) if d.get("lang") == "en"), "")
    met = nvd_metrics(nvd) if nvd else None
    prods = nvd_products(nvd) if nvd else []
    if kev:
        vendor_prod = f'{kev["vendorProject"]} {kev["product"]}'
    elif prods:
        vendor_prod = prods[0].title()
    else:
        vendor_prod = guess_product(desc) or (watch or "").title() or "Produit N/A"
    name = kev.get("vulnerabilityName") if kev else ""
    score = fr_num(met["score"]) if met else "N/A"
    tags = []
    if kev:
        tags.append("KEV")
    if met:
        tags.append(f"CVSS {score}")
    title = f"🚨 {cid} — {vendor_prod}" + (f" · {' · '.join(tags)}" if tags else "")
    rows = [f'<p><strong>Pourquoi cette alerte :</strong> {e(why)}</p>']
    if name:
        rows.append(f"<p><strong>{e(name)}</strong></p>")
    facts = [f'<a href="https://nvd.nist.gov/vuln/detail/{e(cid)}">{e(cid)}</a>']
    facts.append(f"<strong>CVSS</strong> {score}" + (f" (v{e(met['version'])})" if met else ""))
    facts.append(f"<strong>EPSS</strong> {fr_num(ep[0], 3)} · p{fr_num(ep[1] * 100)}" if ep else "<strong>EPSS</strong> N/A")
    facts.append(f"<strong>KEV</strong> {'oui, ajout le ' + e(kev['dateAdded']) if kev else 'non'}")
    rows.append("<p>" + "<br>".join(facts) + "</p>")
    if met and met.get("vector"):
        rows.append(f"<p><small>Vecteur : <code>{e(met['vector'])}</code></small></p>")
    if desc:
        rows.append(f"<blockquote><p>{e(desc)}</p></blockquote>")
    if kev:
        rows.append(f'<p><strong>Action requise (CISA) :</strong> {e(kev.get("requiredAction", ""))}'
                    f'{"<br><strong>Échéance fédérale :</strong> " + e(kev["dueDate"]) if kev.get("dueDate") else ""}'
                    f'{"<br><strong>Utilisée par des ransomwares :</strong> " + e(kev["knownRansomwareCampaignUse"]) if kev.get("knownRansomwareCampaignUse") else ""}</p>')
    if prods:
        rows.append(f"<p><small>Produits (CPE) : {e(', '.join(prods[:8]))}</small></p>")
    refs = [r["url"] for r in (nvd or {}).get("references", [])][:5]
    if refs:
        rows.append("<p><small>Références : " + " · ".join(f'<a href="{e(u)}">{e(urllib.parse.urlparse(u).netloc)}</a>' for u in refs) + "</small></p>")
    return {"id": ("KEV:" if kev else "NVD:") + cid, "title": title, "link": f"https://nvd.nist.gov/vuln/detail/{cid}", "date": NOW.isoformat(),
            "html": "\n".join(rows), "kind": "KEV" if kev else "NVD"}


def main():
    DIR.mkdir(exist_ok=True)
    state = load(STATE, {})
    items = load(ITEMS, [])
    seen = set(state.get("seen", []))
    bootstrap = "last" not in state
    since = dt.datetime.fromisoformat(state["last"]) if not bootstrap else NOW - dt.timedelta(days=3)
    since = max(since, NOW - dt.timedelta(days=7))
    words = watchlist()
    new = []

    kev_new, kev_all = from_kev(since, seen)
    nvd = from_nvd(since)

    cands = {}
    for cid, k in kev_new.items():
        cands[cid] = {"kev": k["kev"], "why": "ajoutée au catalogue KEV de la CISA : exploitation active confirmée."}
    pub_floor = (NOW - dt.timedelta(days=14)).isoformat()
    for cid, c in nvd.items():
        if f"NVD:{cid}" in seen or cid in cands:
            continue
        met = nvd_metrics(c)
        if not met or met["score"] < 9.0:
            continue
        if c.get("published", "") < pub_floor[:19] and cid not in kev_all:
            continue
        vec = met["vector"]
        if "AV:N" not in vec or "PR:N" not in vec:
            continue
        desc = " ".join(d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en")
        if NOISE.search(desc) and cid not in kev_all:
            continue  # plugins/thèmes de CMS : trop de bruit, sauf exploitation confirmée
        w = match_watch(" ".join(nvd_products(c)) + " " + desc, words)
        if not w and cid not in kev_all:
            continue
        cands[cid] = {"kev": None, "watch": w, "why": f"CVSS {fr_num(met['score'])}, exploitable par le réseau sans authentification, produit surveillé ({w})."}
    for cid in cands:
        if cid in nvd and cands[cid]["kev"] is None and cid in kev_all:
            cands[cid]["why"] += " Déjà au KEV."

    missing = [cid for cid in cands if cid not in nvd]
    for cid in missing[:10]:
        data = get(f"{NVD_URL}?cveId={cid}")
        time.sleep(7)
        for it in (data or {}).get("vulnerabilities", []):
            nvd[cid] = it["cve"]
    ep = epss(list(cands)) if cands else {}

    for cid, c in cands.items():
        it = build_cve_item(cid, nvd.get(cid), c["kev"], ep.get(cid), c["why"], c.get("watch"))
        new.append(it)
        seen.add(f"NVD:{cid}")
        if c["kev"]:
            seen.add(f"KEV:{cid}")

    for a in from_certfr(seen):
        seen.add(f"ALE:{a['ref']}")
        if bootstrap:
            continue  # au premier passage, on mémorise les alertes existantes sans les republier
        new.append({"id": a["ref"], "title": f"🇫🇷 {a['ref']} — {a['titre']}", "link": a["url"], "date": NOW.isoformat(), "kind": "CERT-FR",
                    "html": f'<p><strong>Pourquoi cette alerte :</strong> nouvelle alerte du CERT-FR (ANSSI), réservée aux menaces critiques ou exploitées.</p>'
                            f'<p><a href="{e(a["url"])}">Lire l\'alerte sur cert.cyber.gouv.fr →</a></p>'})

    known = {i["id"] for i in items}
    for it in new:
        if it["id"] not in known:
            items.insert(0, it)
    items = items[:60]

    state = {"last": NOW.isoformat(), "seen": sorted(seen)[-6000:], "log": LOG[-10:]}
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=0), encoding="utf-8")
    ITEMS.write_text(json.dumps(items, ensure_ascii=False, indent=1), encoding="utf-8")
    write_feed(items)
    print(f"{len(new)} nouvelle(s) alerte(s) ; {len(items)} dans le flux ; erreurs : {LOG or 'aucune'}")


def write_feed(items):
    rss = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:atom="http://www.w3.org/2005/Atom">',
           "<channel>", "<title>CVE critiques — alertes</title>", f"<link>{BASE}</link>",
           f'<atom:link href="{BASE}critique.xml" rel="self" type="application/rss+xml"/>',
           "<description>Alertes quasi temps réel : ajouts CISA KEV, alertes CERT-FR, CVE CVSS ≥ 9 réseau sans authentification sur produits surveillés.</description>",
           "<language>fr-fr</language>", "<ttl>20</ttl>", f"<lastBuildDate>{format_datetime(NOW)}</lastBuildDate>"]
    for it in items:
        d = dt.datetime.fromisoformat(it["date"])
        rss += ["<item>", f"<title>{e(it['title'])}</title>", f"<link>{e(it['link'])}</link>",
                f'<guid isPermaLink="false">critique-{e(it["id"])}</guid>', f"<pubDate>{format_datetime(d)}</pubDate>",
                f"<category>{e(it['kind'])}</category>",
                "<content:encoded><![CDATA[" + it["html"].replace("]]>", "]]&gt;") + "]]></content:encoded>", "</item>"]
    rss += ["</channel>", "</rss>", ""]
    (ROOT / "critique.xml").write_text("\n".join(rss), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
