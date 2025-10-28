from urllib.parse import urlparse
import tldextract
import re
from rapidfuzz.distance import Levenshtein

COMMON_BRANDS = ["paypal","apple","itau","nubank","bradesco","santander","mercadolivre","instagram","facebook","microsoft","google","gov"]

RISK = {
    "many_subdomains": 8,
    "homoglyph_like": 10,
    "numbers_for_letters": 6,
    "ip_literal": 12,
    "long_url": 5,
    "suspicious_words": 6,
    "non_standard_port": 5,
    "special_chars": 5,
}

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw
    parsed = urlparse(raw)

    clean_query = "&".join([q for q in parsed.query.split("&") if not q.startswith("utm_")]) if parsed.query else ""
    rebuilt = parsed._replace(fragment="", query=clean_query)
    return rebuilt.geturl()

def url_features(url: str) -> dict:
    p = urlparse(url)
    ext = tldextract.extract(p.hostname or "")
    registered = ".".join([ext.domain, ext.suffix]) if ext.suffix else ext.domain
    sub_count = 0 if not ext.subdomain else len(ext.subdomain.split("."))
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", p.hostname or ""))
    long_url = len(url) > 120
    non_std_port = p.port not in (80, 443, None)
    special_chars = bool(re.search(r"[%@;$]", url))
    suspicious_words = any(w in (p.path or "").lower() for w in ["login","verify","atualize","secure","conta","premio","gift","update"])
    # números no domínio substituindo letras (p.ex paypa1)
    has_num_for_letter = bool(re.search(r"[a-z]+[0-9][a-z]+", ext.domain or ""))
    # similaridade com marcas
    looks_like_brand = False
    if ext.domain:
        for brand in COMMON_BRANDS:
            if Levenshtein.distance(ext.domain.lower(), brand) <= 1:
                looks_like_brand = True
                break
    return {
        "host": p.hostname,
        "registered_domain": registered,
        "subdomain_count": sub_count,
        "is_ip_literal": is_ip,
        "url_length_gt_120": long_url,
        "non_standard_port": non_std_port,
        "special_chars": special_chars,
        "suspicious_words": suspicious_words,
        "numbers_for_letters": has_num_for_letter,
        "brand_lookalike": looks_like_brand,
    }

def heuristic_score(feat: dict) -> tuple[int, list[str]]:
    score = 0
    evidence = []
    if feat["is_ip_literal"]: score += RISK["ip_literal"]; evidence.append("Host é IP literal")
    if feat["subdomain_count"] >= 3: score += RISK["many_subdomains"]; evidence.append("Excesso de subdomínios")
    if feat["numbers_for_letters"]: score += RISK["numbers_for_letters"]; evidence.append("Números no lugar de letras")
    if feat["url_length_gt_120"]: score += RISK["long_url"]; evidence.append("URL muito longa")
    if feat["suspicious_words"]: score += RISK["suspicious_words"]; evidence.append("Palavras de isca no caminho")
    if feat["non_standard_port"]: score += RISK["non_standard_port"]; evidence.append("Porta não padrão")
    if feat["special_chars"]: score += RISK["special_chars"]; evidence.append("Caracteres especiais na URL")
    if feat["brand_lookalike"]: score += RISK["homoglyph_like"]; evidence.append("Parecido com marca conhecida")
    return score, evidence