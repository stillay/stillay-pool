#!/usr/bin/env python3
"""Сбор бесплатных конфигов из публичных списков.

Скачивает списки, раскодирует base64, оставляет только шифрованные протоколы
(vless+tls/reality, trojan, vmess, ss, hysteria2, tuic), выкидывает дубли,
приватные адреса и конфиги с отключённой проверкой сертификата, проверяет
доступность TCP-порта, оставляет самые быстрые и переименовывает в "stillayvpn".

Запуск как скрипта:  python aggregate.py --out sub.txt
"""
import argparse
import asyncio
import base64
import ipaddress
import json
import random
import re
import sys
import time
from urllib.parse import parse_qs, quote, unquote, urlparse

DEFAULT_SOURCES = [
    f"https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/{i}.txt"
    for i in range(1, 11)
]

LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://", re.I | re.M)
LINE_RE = re.compile(r"^(vless|vmess|trojan|ss|hysteria2|hy2|tuic)://", re.I)
FLAG_RE = re.compile("[\U0001F1E6-\U0001F1FF]{2}")
UDP_SCHEMES = {"hysteria2", "hy2", "tuic"}


def _b64(s: str) -> str:
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")


def extract_links(text: str) -> list:
    text = text.replace("\r", "")
    if not LINK_RE.search(text):
        try:
            text = _b64(text)
        except Exception:
            return []
    out = []
    for ln in text.split("\n"):
        ln = ln.strip()
        if LINE_RE.match(ln):
            out.append(ln)
    return out


def parse(link: str):
    """Возвращает dict с полями scheme/host/port/name/params или None."""
    m = LINE_RE.match(link)
    if not m:
        return None
    scheme = m.group(1).lower()
    try:
        if scheme == "vmess":
            d = json.loads(_b64(link[8:]))
            host, port, name = str(d.get("add", "")), int(d.get("port")), str(d.get("ps", ""))
            params, extra = {}, d
        else:
            u = urlparse(link)
            host, port = u.hostname, u.port
            name = unquote(u.fragment)
            params = {k: v[0] for k, v in parse_qs(u.query).items()}
            extra = None
            if scheme == "ss" and (not host or not port):
                body = link[5:].split("#")[0].split("?")[0]
                hp = _b64(body).rsplit("@", 1)[1]
                host, port = hp.rsplit(":", 1)
                port = int(port)
        if not host or not port or not (1 <= int(port) <= 65535):
            return None
        host = host.strip("[]")
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                return None
        except ValueError:
            if "." not in host:
                return None
        return {"scheme": scheme, "host": host, "port": int(port), "name": name,
                "params": params, "vmess": extra}
    except Exception:
        return None


def acceptable(p: dict, allow_insecure: bool = False) -> bool:
    q = p["params"]
    ins = str(q.get("allowInsecure", q.get("insecure", ""))).lower() in ("1", "true")
    if ins and not allow_insecure:
        return False
    sec = str(q.get("security", "")).lower()
    if p["scheme"] == "vless" and sec not in ("tls", "reality"):
        return False
    if p["scheme"] == "trojan" and sec == "none":
        return False
    return True


def rename(link: str, p: dict, new_name: str) -> str:
    if p["scheme"] == "vmess":
        d = dict(p["vmess"])
        d["ps"] = new_name
        raw = json.dumps(d, ensure_ascii=False).encode()
        return "vmess://" + base64.b64encode(raw).decode()
    return link.split("#", 1)[0] + "#" + quote(new_name)


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    async with sem:
        t = time.perf_counter()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        except Exception:
            return None
        dt = time.perf_counter() - t
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass
        return dt


async def fetch(src: str, log) -> str:
    try:
        if src.startswith(("http://", "https://")):
            import aiohttp
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=120)) as s:
                async with s.get(src, headers={"User-Agent": "Mozilla/5.0"}) as r:
                    if r.status != 200:
                        log(f"источник {src}: HTTP {r.status}")
                        return ""
                    return await r.text(errors="ignore")
        with open(src, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        log(f"источник {src}: {e}")
        return ""


def finalize(entries: list, name: str = "stillayvpn") -> list:
    """Нумерует и переименовывает выбранные конфиги в name <флаг> <номер>."""
    out = []
    for i, e in enumerate(entries, 1):
        m = FLAG_RE.search(e["p"]["name"])
        nm = f"{name} {m.group(0)} {i}" if m else f"{name} {i}"
        out.append(rename(e["link"], e["p"], nm))
    return out


async def build(sources=None, pool_size=300, probe_limit=4000, udp_pool=30,
                probe_timeout=4.0, concurrency=100, allow_insecure=False,
                do_probe=True, select="random", log=print):
    """Возвращает пул живых конфигов (список {"link", "p"}) и статистику.

    select="random": из живых берутся случайные, скорость не учитывается.
    select="fast": берутся самые быстрые по времени TCP-соединения.
    """
    sources = list(sources or DEFAULT_SOURCES)
    texts = await asyncio.gather(*(fetch(s, log) for s in sources))
    per_source = max(200, probe_limit // max(1, len(sources)))
    seen, tcp, udp = set(), [], []
    stats = {"links": 0}
    for text in texts:
        links = list({ln.split("#", 1)[0]: ln for ln in extract_links(text)}.values())
        stats["links"] += len(links)
        random.shuffle(links)
        taken = 0
        for ln in links:
            if taken >= per_source:
                break
            p = parse(ln)
            if not p or not acceptable(p, allow_insecure):
                continue
            key = (p["scheme"], p["host"].lower(), p["port"])
            if key in seen:
                continue
            seen.add(key)
            (udp if p["scheme"] in UDP_SCHEMES else tcp).append((ln, p))
            taken += 1
    stats.update(candidates_tcp=len(tcp), candidates_udp=len(udp))

    alive = []
    if do_probe and tcp:
        sem = asyncio.Semaphore(concurrency)
        res = await asyncio.gather(*(probe(p["host"], p["port"], probe_timeout, sem) for _, p in tcp))
        alive = sorted(((dt, ln, p) for (ln, p), dt in zip(tcp, res) if dt is not None),
                       key=lambda x: x[0])
    else:
        alive = [(0.0, ln, p) for ln, p in tcp]
    stats["alive_tcp"] = len(alive)

    if select != "fast":
        random.shuffle(alive)
    random.shuffle(udp)
    pool = [{"link": ln, "p": p} for _, ln, p in alive[:pool_size]]
    pool += [{"link": ln, "p": p} for ln, p in udp[:udp_pool]]
    stats["pool"] = len(pool)
    return pool, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sub.txt")
    ap.add_argument("--name", default="stillayvpn")
    ap.add_argument("--max", type=int, default=60)
    ap.add_argument("--sources", help="файл со списком источников (по одному в строке)")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--allow-insecure", action="store_true")
    ap.add_argument("--select", choices=["fast", "random"], default="fast")
    ap.add_argument("--pool-out", help="записать пул живых серверов (для воркера) и выйти")
    ap.add_argument("--pool-size", type=int, default=300)
    a = ap.parse_args()
    src = None
    if a.sources:
        src = [s.strip() for s in open(a.sources, encoding="utf-8") if s.strip() and not s.startswith("#")]
    if a.pool_out:
        pool, st = asyncio.run(build(src, pool_size=a.pool_size, udp_pool=30,
                                     allow_insecure=a.allow_insecure,
                                     do_probe=not a.no_probe, select="random"))
        if not pool:
            print("пул пуст, файл не обновлён", file=sys.stderr)
            sys.exit(1)
        with open(a.pool_out, "w", encoding="utf-8") as f:
            f.write(f"#updated: {int(time.time())}\n")
            f.write("\n".join(e["link"] for e in pool) + "\n")
        print(st, file=sys.stderr)
        return
    pool, st = asyncio.run(build(src, pool_size=max(1, a.max - 10), udp_pool=10,
                                 allow_insecure=a.allow_insecure,
                                 do_probe=not a.no_probe, select=a.select))
    links = finalize(pool, a.name)
    head = f"#profile-title: {a.name}\n#profile-update-interval: 6\n"
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(head + "\n".join(links) + "\n")
    print(st, file=sys.stderr)


if __name__ == "__main__":
    main()
