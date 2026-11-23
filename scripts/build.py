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
def fragment(d):
    o = [f'<p><b>TLP:CLEAR</b> · {e(d["periode"])}</p>',
         f'<p><b>Niveau de menace : {NIV[d["niveau"]]}</b> — {e(d["justification"])}</p>',
         "<h2>L'essentiel (BLUF)</h2><ul>"]
    o += [f'<li>{PRIO.get(b["p"], "")} <b>{e(b["sujet"])} :</b> {e(b["texte"])}</li>' for b in d["bluf"]]
    o.append("</ul><h2>Vulnérabilités</h2>")
    if d.get("alertes"):
        o.append(f'<p><i>{e(d["alertes"])}</i></p>')
    for v in d["vulns"]:
        o.append(f'<h3>{PRIO.get(v["prio"], "")} · {e(v["titre"])}</h3>')
        o.append(f'<p><code>{e(", ".join(v["cves"]))}</code> · CVSS <b>{e(v["cvss"])}</b> ({e(v["cvssv"])}) · '
                 f'EPSS {e(v["epss"])}{" (p" + e(v["pct"]) + ")" if v.get("pct") else ""} · '
                 f'KEV {"<b>oui</b>" if v.get("kev") else "non"} · Exploitation : {e(v["exploit"])} · PoC : {e(v["poc"])}</p>')
        o.append(f'<p><b>Produit :</b> {e(v["produit"])}<br><b>Type :</b> {e(v["type"])}<br><b>Correctif :</b> {e(v["correctif"])}</p>')
        if v.get("quoi"):
            for lab, k in [("Quoi ?", "quoi"), ("Comment ?", "comment"), ("Pourquoi c'est important ?", "pourquoi"),
                           ("Détection", "detection"), ("Remédiation", "remediation")]:
                o.append(f'<p><b>{lab}</b><br>{e(v.get(k, "N/A"))}</p>')
        elif v.get("resume"):
            o.append(f'<p>{e(v["resume"])}</p>')
        if v.get("sources"):
            o.append(f'<p><small>Sources : {src_html(v["sources"])}</small></p>')
    o.append("<h2>Menaces &amp; campagnes</h2>")
    for m in d["menaces"]:
        o.append(f'<h3>{e(m["titre"])}</h3>')
        if m.get("comment") or m.get("pourquoi"):
            for lab, k in [("Quoi ?", "quoi"), ("Comment ?", "comment"), ("Pourquoi c'est important ?", "pourquoi")]:
                o.append(f'<p><b>{lab}</b><br>{e(m.get(k, "N/A"))}</p>')
        else:
            o.append(f'<p>{e(m["quoi"])}</p>')
        if m.get("acteur") and m["acteur"] != "N/A":
            o.append(f'<p><b>Attribution :</b> {e(m["acteur"])} · confiance {CONF.get(m.get("confiance", 0))}</p>')
        if m.get("ttps"):
            o.append("<p><b>TTPs :</b> " + ", ".join(f'<a href="{ttp_url(t[0])}">{e(t[0])} {e(t[1])}</a>' for t in m["ttps"]) + "</p>")
        o.append(f'<p><small>Sources : {src_html(m.get("sources"))}</small></p>')
    rw = d["ransomware"]
    o.append("<h2>Ransomware — France</h2><ul>")
    o += [f'<li><b>{e(r["victime"])}</b> — {e(r["groupe"])} · {e(r["secteur"])} · {e(r["date"])} · '
          f'<i>{e(r["statut"])}</i>. {e(r.get("note", ""))}</li>' for r in rw.get("victimes", [])] or ["<li>Aucune revendication visant la France.</li>"]
    o.append("</ul>")
    if rw.get("tendance"):
        g = ", ".join(f"{x[0]} ({x[1]})" for x in rw.get("groupes", []))
        o.append(f'<p>{e(rw["tendance"])} {("Groupes les plus actifs : " + e(g) + ".") if g else ""}</p>')
    o.append("<h2>Fuites de données</h2><ul>")
    o += [f'<li><b>{e(f["victime"])}</b> ({e(f["pays"])}) — {e(f["volume"])} · {e(f["donnees"])} · <i>{e(f["statut"])}</i>'
          f'{" · " + src_html([f["source"]]) if f.get("source") else ""}</li>' for f in d["fuites"]]
    o.append("</ul>")
    if d.get("iocs"):
        o.append("<h2>IOC notables</h2><ul>")
        o += [f'<li>{e(i["type"])} : <code>{e(i["valeur"])}</code> — {e(i["contexte"])} ({e(i["source"])})</li>' for i in d["iocs"]]
        o.append("</ul>")
    if d.get("regl"):
        o.append("<h2>Réglementaire &amp; institutionnel</h2><ul>" + "".join(f"<li>{e(r)}</li>" for r in d["regl"]) + "</ul>")
    if d.get("lab"):
        o.append(f'<h2>À creuser</h2><p><b>Concept :</b> {e(d["lab"]["concept"])}</p><p><b>Piste de lab :</b> {e(d["lab"]["piste"])}</p>')
    o.append(f'<hr><p><small>Sources consultées : {e(d.get("consultees", ""))}. Indisponibles : {e(d.get("indispo", "aucune"))}.</small></p>')
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
        url = f"{BASE}bulletins/{day}.html"
        desc = f'Niveau {NIV[d["niveau"]]} — {d["justification"]}'
        rss += ["<item>", f"<title>{e('Bulletin CTI — ' + d['date'] + ' · Niveau ' + NIV[d['niveau']])}</title>",
                f"<link>{url}</link>", f'<guid isPermaLink="true">{url}</guid>', f"<pubDate>{pub}</pubDate>",
                f"<description>{e(desc)}</description>",
                "<content:encoded><![CDATA[" + fragment(d).replace("]]>", "]]&gt;") + "]]></content:encoded>", "</item>"]
    rss += ["</channel>", "</rss>", ""]
    (ROOT / "feed.xml").write_text("\n".join(rss), encoding="utf-8")

    if items:
        (ROOT / "latest.html").write_text(page(items[0][1], tpl), encoding="utf-8")
    rows = "".join(f'<li><a href="bulletins/{day}.html">{e(d["date"])}</a> <span>Niveau {NIV[d["niveau"]]}</span> '
                   f'<a class="md" href="bulletins/{day}.md">.md</a></li>' for day, d in items)
    latest = (f'<a class="last" href="latest.html"><small>Dernier bulletin · Niveau {NIV[items[0][1]["niveau"]]}</small>'
              f'<b>{e(items[0][1]["date"])}</b><span>{e(items[0][1]["justification"])}</span></a>') if items else ""
    (ROOT / "index.html").write_text(f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bulletin CTI quotidien</title>
<link rel="alternate" type="application/rss+xml" title="Bulletin CTI quotidien" href="{BASE}feed.xml">
<link rel="manifest" href="/veille-cti/manifest.webmanifest">
<link rel="apple-touch-icon" href="/veille-cti/icons/apple-touch-icon.png">
<link rel="icon" type="image/png" href="/veille-cti/icons/icon-192.png">
<meta name="theme-color" content="#141517"><meta name="apple-mobile-web-app-capable" content="yes">
<style>
body{{margin:0;background:#e9eaec;color:#111214;font:16px/1.55 system-ui,sans-serif;padding:32px max(4vw,16px)}}
@media(prefers-color-scheme:dark){{body{{background:#141517;color:#ececed}}a{{color:#ececed}}}}
h1{{font-size:40px;line-height:1.05;margin:0 0 8px;font-weight:600}}
ul{{list-style:none;padding:0;max-width:720px}} li{{display:flex;gap:12px;padding:10px 0;border-top:1px solid #8884;flex-wrap:wrap}}
.last{{display:grid;gap:4px;max-width:720px;margin:18px 0;padding:18px;border-radius:10px;background:#111214;color:#ececed;text-decoration:none;border-left:6px solid #ff4f00}}
.last small{{opacity:.7}} .last b{{font-size:22px}} .last span{{opacity:.85}}
span{{opacity:.7}} .md{{margin-left:auto;font-size:14px}} a{{color:inherit;text-decoration-color:#ff4f00}}
</style></head><body>
<h1>Bulletin CTI quotidien</h1>
{latest}
<p>Flux RSS : <a href="feed.xml">{BASE}feed.xml</a></p>
<ul>{rows}</ul>
</body></html>
""", encoding="utf-8")
    print(f"{len(items)} bulletin(s) construits ; feed.xml : {min(30, len(items))} items")


if __name__ == "__main__":
    main()
