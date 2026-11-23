#!/usr/bin/env python3
"""Construit le site veille-cti à partir des fichiers data/AAAA-MM-JJ.json.

Fichiers acceptés : data/AAAA-MM-JJ.json ou data/AAAA-MM-JJ-HHMM.json (édition supplémentaire).
Pour chaque bulletin : bulletins/<date>.html (page complète), bulletins/<date>.md (note Obsidian).
Puis régénère feed.xml (30 derniers bulletins, contenu complet) et index.html (archive).
Usage : python3 scripts/build.py
"""
import json, re, html, pathlib, datetime
from email.utils import format_datetime
from zoneinfo import ZoneInfo

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = "https://theophanelg.github.io/veille-cti/"
PARIS = ZoneInfo("Europe/Paris")
NIV = ["Faible", "Modéré", "Élevé", "Critique"]
PRIO = {1: "🔴 P1", 2: "🟠 P2", 3: "⚪ P3"}
CONF = {0: "N/A", 1: "faible", 2: "moyenne", 3: "élevée"}
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)


def ttp_url(t):
    return "https://attack.mitre.org/techniques/" + t.replace(".", "/") + "/"


def src_html(lst):
    return " · ".join(f'<a href="{e(s["u"])}">{e(s["t"])}</a>' if s.get("u") else e(s["t"]) for s in lst or [])


def src_md(lst):
    return " · ".join(f'[{s["t"]}]({s["u"]})' if s.get("u") else s["t"] for s in lst or [])


def validate(d):
    for k in ["date", "periode", "niveau", "justification", "bluf", "vulns", "menaces", "ransomware", "fuites"]:
        if k not in d:
            raise SystemExit(f"clé manquante : {k}")
    if json.dumps(d, ensure_ascii=False).find("</") >= 0:
        raise SystemExit("une chaîne contient '</'")


# ---------- page HTML (modèle + données) ----------
def page(d, tpl):
    data = json.dumps(d, ensure_ascii=False, indent=1)
    return re.sub(r'(<script id="data" type="application/json">).*?(</script>)',
                  lambda m: m.group(1) + "\n" + data + "\n" + m.group(2), tpl, count=1, flags=re.S)


# ---------- fragment HTML statique pour les lecteurs RSS ----------
LVL_EMO = ["🟢", "🟡", "🟠", "🔴"]
MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]
JOURS = ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."]


def short_title(day, d):
    y, m, j = map(int, day[:10].split("-"))
    dt = datetime.date(y, m, j)
    hm = day[11:15]
    when = f"{JOURS[dt.weekday()]} {j} {MOIS[m - 1]}" + (f" ({hm[:2]}h{hm[2:]})" if hm else "")
    sujets = [re.sub(r"\s*\(.*?\)", "", b["sujet"]).split(",")[0].strip() for b in d["bluf"][:3]]
    return f'{LVL_EMO[d["niveau"]]} {NIV[d["niveau"]]} · {when} — {", ".join(sujets)}'


def fragment(d, day=""):
    """HTML simple et aéré pour les lecteurs RSS (NetNewsWire, Obsidian…) : pas de CSS, balises sémantiques."""
    lien = f"{BASE}#{day}" if day else BASE
    o = [f'<p><strong>{LVL_EMO[d["niveau"]]} Niveau {NIV[d["niveau"]]}</strong> — {e(d["justification"])}</p>',
         f'<p><small>TLP:CLEAR · {e(d["periode"])}<br><a href="{lien}">Ouvrir dans l\'interface →</a></small></p>',
         "<h2>L'essentiel</h2><ul>"]
    o += [f'<li>{PRIO.get(b["p"], "")[:2]} <strong>{e(b["sujet"])}</strong> — {e(b["texte"])}</li>' for b in d["bluf"]]
    o.append("</ul>")

    if d["vulns"]:
        o.append("<hr><h2>Vulnérabilités</h2>")
        if d.get("alertes"):
            o.append(f'<p><em>{e(d["alertes"])}</em></p>')
    for v in d["vulns"]:
        o.append(f'<h3>{PRIO.get(v["prio"], "")} · {e(v["titre"])}</h3>')
        ids = ", ".join(f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}">{e(c)}</a>' for c in v["cves"]) or "Pas de CVE"
        expl = "oui" if str(v.get("exploit", "")).lower().startswith("oui") else e(v.get("exploit", "N/A"))
        o.append(f'<p>{ids}<br><strong>CVSS</strong> {e(v["cvss"])} · <strong>EPSS</strong> {e(v["epss"])} · '
                 f'<strong>KEV</strong> {"oui" if v.get("kev") else "non"}<br><strong>Exploitée</strong> : {expl} · '
                 f'<strong>PoC</strong> : {e(v["poc"])}</p>')
        if v.get("quoi"):
            o.append(f'<p><strong>Quoi.</strong> {e(v["quoi"])}</p>')
            o.append(f'<p><strong>Comment.</strong> {e(v["comment"])}</p>')
            o.append(f'<p><strong>Pourquoi c\'est important.</strong> {e(v["pourquoi"])}</p>')
            o.append(f'<blockquote><p><strong>Détecter :</strong> {e(v["detection"])}</p>'
                     f'<p><strong>Corriger :</strong> {e(v["remediation"])}</p></blockquote>')
        elif v.get("resume"):
            o.append(f'<p>{e(v["resume"])}</p>')
        o.append(f'<p><small><strong>Produit :</strong> {e(v["produit"])}<br><strong>Correctif :</strong> {e(v["correctif"])}'
                 f'{"<br>Sources : " + src_html(v["sources"]) if v.get("sources") else ""}</small></p>')

    if d["menaces"]:
        o.append("<hr><h2>Menaces &amp; campagnes</h2>")
    for m in d["menaces"]:
        o.append(f'<h3>{e(m["titre"])}</h3>')
        if m.get("comment") or m.get("pourquoi"):
            o.append(f'<p><strong>Quoi.</strong> {e(m["quoi"])}</p>')
            o.append(f'<p><strong>Comment.</strong> {e(m.get("comment", "N/A"))}</p>')
            o.append(f'<p><strong>Pourquoi c\'est important.</strong> {e(m.get("pourquoi", "N/A"))}</p>')
        else:
            o.append(f'<p>{e(m["quoi"])}</p>')
        extra = []
        if m.get("acteur") and m["acteur"] != "N/A":
            extra.append(f'<strong>Attribution :</strong> {e(m["acteur"])} (confiance {CONF.get(m.get("confiance", 0))})')
        if m.get("ttps"):
            extra.append("<strong>TTPs :</strong> " + ", ".join(f'<a href="{ttp_url(t[0])}">{e(t[0])}</a> {e(t[1])}' for t in m["ttps"]))
        if m.get("sources"):
            extra.append("Sources : " + src_html(m["sources"]))
        if extra:
            o.append("<p><small>" + "<br>".join(extra) + "</small></p>")

    rw = d["ransomware"]
    o.append("<hr><h2>Ransomware — France</h2>")
    if rw.get("victimes"):
        o.append("<ul>" + "".join(f'<li><strong>{e(r["victime"])}</strong> — {e(r["groupe"])}, {e(r["secteur"])}, {e(r["date"])}. '
                                   f'<em>{e(r["statut"])}</em>{". " + e(r["note"]) if r.get("note") else ""}</li>'
                                   for r in rw["victimes"]) + "</ul>")
    else:
        o.append("<p>Aucune revendication visant la France.</p>")
    if rw.get("tendance"):
        g = ", ".join(f"{x[0]} ({x[1]})" for x in rw.get("groupes", []))
        o.append(f'<p><small>{e(rw["tendance"])}{(" Plus actifs : " + e(g) + ".") if g else ""}</small></p>')

    if d["fuites"]:
        o.append("<hr><h2>Fuites de données</h2><ul>")
        o += [f'<li><strong>{e(f["victime"])}</strong> ({e(f["pays"])}) — {e(f["volume"])}. {e(f["donnees"])}. '
              f'<em>{e(f["statut"])}</em>{" · " + src_html([f["source"]]) if f.get("source") else ""}</li>' for f in d["fuites"]]
        o.append("</ul>")
    if d.get("iocs"):
        o.append("<hr><h2>IOC</h2><ul>")
        o += [f'<li><code>{e(i["valeur"])}</code> — {e(i["type"])}, {e(i["contexte"])}</li>' for i in d["iocs"]]
        o.append("</ul>")
    if d.get("regl"):
        o.append("<hr><h2>Réglementaire</h2><ul>" + "".join(f"<li>{e(r)}</li>" for r in d["regl"]) + "</ul>")
    if d.get("lab"):
        o.append(f'<hr><h2>À creuser</h2><p><strong>Concept.</strong> {e(d["lab"]["concept"])}</p>'
                 f'<blockquote><p><strong>Piste de lab :</strong> {e(d["lab"]["piste"])}</p></blockquote>')
    o.append(f'<hr><p><small>Sources consultées : {e(d.get("consultees", ""))}.<br>Indisponibles : {e(d.get("indispo", "aucune"))}.</small></p>')
    return "\n".join(o)


# ---------- note Markdown pour Obsidian ----------
def markdown(d, day):
    cves = sorted({c for v in d["vulns"] for c in v["cves"]})
    q = lambda s: str(s).replace('"', "'")
    o = ["---", f"date: {day[:10]}", f'titre: "Bulletin CTI — {q(d["date"])}"', f"niveau: {NIV[d['niveau']]}",
         "tlp: CLEAR", "tags: [veille-cti, bulletin]", "cves: [" + ", ".join(cves) + "]",
         f"lien: {BASE}bulletins/{day}.html", "---", "",
         f"# Bulletin CTI — {d['date']}", "",
         f"> [!abstract] Niveau de menace : **{NIV[d['niveau']]}**", f"> {d['justification']}", f"> Période : {d['periode']}", "",
         "## L'essentiel (BLUF)"]
    o += [f"- {PRIO.get(b['p'], '')} **{b['sujet']} :** {b['texte']}" for b in d["bluf"]]
    o += ["", "## Vulnérabilités"]
    if d.get("alertes"):
        o += ["", f"*{d['alertes']}*"]
    for v in d["vulns"]:
        kind = {1: "danger", 2: "warning", 3: "note"}.get(v["prio"], "note")
        o += ["", f"> [!{kind}] {PRIO.get(v['prio'], '')} · {v['titre']}",
              f"> `{', '.join(v['cves'])}` · CVSS **{v['cvss']}** ({v['cvssv']}) · EPSS {v['epss']}"
              f"{' (p' + v['pct'] + ')' if v.get('pct') else ''} · KEV {'**oui**' if v.get('kev') else 'non'} · "
              f"Exploitation : {v['exploit']} · PoC : {v['poc']}",
              f"> **Produit :** {v['produit']}", f"> **Type :** {v['type']}", f"> **Correctif :** {v['correctif']}"]
        if v.get("quoi"):
            for lab, k in [("Quoi ?", "quoi"), ("Comment ?", "comment"), ("Pourquoi c'est important ?", "pourquoi"),
                           ("Détection", "detection"), ("Remédiation", "remediation")]:
                o += [">", f"> **{lab}** {v.get(k, 'N/A')}"]
        elif v.get("resume"):
            o += [">", f"> {v['resume']}"]
        if v.get("sources"):
            o += [">", f"> Sources : {src_md(v['sources'])}"]
    o += ["", "## Menaces & campagnes"]
    for m in d["menaces"]:
        o += ["", f"### {m['titre']}"]
        if m.get("comment") or m.get("pourquoi"):
            o += [f"- **Quoi ?** {m.get('quoi', 'N/A')}", f"- **Comment ?** {m.get('comment', 'N/A')}",
                  f"- **Pourquoi c'est important ?** {m.get('pourquoi', 'N/A')}"]
        else:
            o.append(m["quoi"])
        if m.get("acteur") and m["acteur"] != "N/A":
            o.append(f"- **Attribution :** {m['acteur']} · confiance {CONF.get(m.get('confiance', 0))}")
        if m.get("ttps"):
            o.append("- **TTPs :** " + ", ".join(f"[{t[0]} {t[1]}]({ttp_url(t[0])})" for t in m["ttps"]))
        o.append(f"- Sources : {src_md(m.get('sources'))}")
    rw = d["ransomware"]
    o += ["", "## Ransomware — France", "", "| Victime | Groupe | Secteur | Date | Statut |", "|---|---|---|---|---|"]
    o += [f"| {r['victime']} | {r['groupe']} | {r['secteur']} | {r['date']} | {r['statut']} |" for r in rw.get("victimes", [])]
    if rw.get("tendance"):
        g = ", ".join(f"{x[0]} ({x[1]})" for x in rw.get("groupes", []))
        o += ["", rw["tendance"] + (f" Groupes les plus actifs : {g}." if g else "")]
    o += ["", "## Fuites de données", "", "| Victime | Pays | Volume | Données | Statut | Source |", "|---|---|---|---|---|---|"]
    o += [f"| {f['victime']} | {f['pays']} | {f['volume']} | {f['donnees']} | {f['statut']} | {src_md([f['source']]) if f.get('source') else ''} |" for f in d["fuites"]]
    if d.get("iocs"):
        o += ["", "## IOC notables", "", "| Type | Valeur | Contexte | Source |", "|---|---|---|---|"]
        o += [f"| {i['type']} | `{i['valeur']}` | {i['contexte']} | {i['source']} |" for i in d["iocs"]]
    if d.get("regl"):
        o += ["", "## Réglementaire & institutionnel"] + [f"- {r}" for r in d["regl"]]
    if d.get("lab"):
        o += ["", "## À creuser", "", "> [!tip] Lab", f"> **Concept :** {d['lab']['concept']}", ">", f"> **Piste de lab :** {d['lab']['piste']}"]
    o += ["", "---", f"*Sources consultées : {d.get('consultees', '')}. Indisponibles : {d.get('indispo', 'aucune')}.*", ""]
    return "\n".join(o)


def main():
    tpl = (ROOT / "template.html").read_text(encoding="utf-8")
    items = []
    for f in sorted((ROOT / "data").glob("????-??-??*.json")):
        day = f.stem
        d = json.loads(f.read_text(encoding="utf-8"))
        validate(d)
        (ROOT / "bulletins" / f"{day}.html").write_text(page(d, tpl), encoding="utf-8")
        (ROOT / "bulletins" / f"{day}.md").write_text(markdown(d, day), encoding="utf-8")
        items.append((day, d))
    items.sort(key=lambda x: x[0], reverse=True)

    now = format_datetime(datetime.datetime.now(PARIS))
    rss = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:atom="http://www.w3.org/2005/Atom">',
           "<channel>", "<title>Bulletin CTI quotidien</title>", f"<link>{BASE}</link>",
           f'<atom:link href="{BASE}feed.xml" rel="self" type="application/rss+xml"/>',
           "<description>Bulletin de veille cybersécurité quotidien : vulnérabilités exploitées, menaces, ransomware, fuites de données.</description>",
           "<language>fr-fr</language>", f"<lastBuildDate>{now}</lastBuildDate>"]
    for day, d in items[:30]:
        y, m, j = map(int, day[:10].split("-"))
        hm = day[11:15] if len(day) >= 15 else "0635"
        pub = format_datetime(datetime.datetime(y, m, j, int(hm[:2]), int(hm[2:]), tzinfo=PARIS))
        url = f"{BASE}#{day}"
        desc = f'Niveau {NIV[d["niveau"]]} — {d["justification"]}'
        rss += ["<item>", f"<title>{e(short_title(day, d))}</title>",
                f"<link>{url}</link>", f'<guid isPermaLink="true">{url}</guid>', f"<pubDate>{pub}</pubDate>",
                f"<description>{e(desc)}</description>",
                "<content:encoded><![CDATA[" + fragment(d, day).replace("]]>", "]]&gt;") + "]]></content:encoded>", "</item>"]
    rss += ["</channel>", "</rss>", ""]
    (ROOT / "feed.xml").write_text("\n".join(rss), encoding="utf-8")

    if items:
        (ROOT / "latest.html").write_text(page(items[0][1], tpl), encoding="utf-8")
    idx = []
    for day, d in items:
        hm = day[11:15]
        texts = [d["date"], d.get("justification", "")] + [b["sujet"] + " " + b["texte"] for b in d["bluf"]]
        texts += [v["titre"] + " " + v.get("produit", "") + " " + " ".join(v["cves"]) for v in d["vulns"]]
        texts += [m["titre"] + " " + m.get("acteur", "") for m in d["menaces"]]
        texts += [r["victime"] + " " + r["groupe"] for r in d["ransomware"].get("victimes", [])]
        texts += [f["victime"] for f in d["fuites"]]
        idx.append({"id": day, "date": d["date"], "niveau": d["niveau"],
                    "edition": f"Édition de {hm[:2]}h{hm[2:]}" if hm else "Édition du matin",
                    "p1": sum(1 for v in d["vulns"] if v["prio"] == 1),
                    "resume": " · ".join(b["sujet"] for b in d["bluf"][:3]),
                    "cves": sorted({c for v in d["vulns"] for c in v["cves"]}),
                    "search": " ".join(texts).lower()})
    shell = (ROOT / "scripts" / "index_template.html").read_text(encoding="utf-8")
    (ROOT / "index.html").write_text(shell.replace("__DATA__", json.dumps(idx, ensure_ascii=False).replace("</", "<\\/")), encoding="utf-8")
    print(f"{len(items)} bulletin(s) construits ; feed.xml : {min(30, len(items))} items")


if __name__ == "__main__":
    main()
