# ip_agent.py (fixed)
import requests, ipaddress, json
from datetime import datetime, timezone
from typing import Dict, Any

# =============== API 키 설정 ===============
API_KEYS = {
    "ipinfo":     "111",
    "abuseipdb":  "222",   # 없으면 "" → 건너뜀
    "virustotal": "333",          # 없으면 "" → 건너뜀
    "crowdsec":   "444",  # 없으면 "" → 건너뜀
    "otx":        "555",         # 없으면 "" → 건너뜀
    "openai":     "666",
}
# =========================================

def ipinfo_lookup(ip, token):
    r = requests.get(f"https://ipinfo.io/{ip}", params={"token": token}, timeout=8)
    r.raise_for_status()
    j = r.json()
    asn, org_name = None, j.get("org")
    if org_name and org_name.startswith("AS"):
        parts = org_name.split(" ", 1)
        asn, org_name = parts[0], (parts[1] if len(parts)>1 else None)
    return {
        "country": j.get("country"),
        "region": j.get("region"),
        "city": j.get("city"),
        "loc": j.get("loc"),
        "asn": asn,
        "org": org_name or j.get("org"),
        "hostname": j.get("hostname"),
        "timezone": j.get("timezone"),
        "anycast": j.get("anycast", False),
    }

def abuseipdb_lookup(ip, key):
    if not key: return {"skipped": True}
    url = "https://api.abuseipdb.com/api/v2/check"
    r = requests.get(url, headers={"Key": key, "Accept":"application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=12)
    if r.status_code == 429: return {"rate_limited": True}
    if r.status_code == 401: return {"unauthorized": True}
    r.raise_for_status()
    d = r.json().get("data", {}) or {}
    cats = []
    for rep in (d.get("reports") or [])[:5]:
        cats = list({*cats, *(rep.get("categories") or [])})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "recent_categories": cats,
        "last_reported_at": d.get("lastReportedAt"),
    }

def virustotal_ip_lookup(ip, key):
    if not key: return {"skipped": True}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    r = requests.get(url, headers={"x-apikey": key}, timeout=12)
    if r.status_code in (204, 429): return {"rate_limited": True}
    if r.status_code == 401: return {"unauthorized": True}
    r.raise_for_status()
    data = r.json().get("data", {}).get("attributes", {}) or {}
    stats = data.get("last_analysis_stats", {}) or {}
    # VT는 relationships로 더 풍부하게 가져올 수 있지만 데모는 핵심만
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":  stats.get("harmless", 0),
        "undetected":stats.get("undetected", 0),
    }

def crowdsec_lookup(ip, key):
    if not key: return {"skipped": True}
    url = f"https://cti.api.crowdsec.net/v2/smoke/ips/{ip}"
    r = requests.get(url, headers={"X-Api-Key": key}, timeout=12)
    if r.status_code == 429: return {"rate_limited": True}
    if r.status_code == 401: return {"unauthorized": True}
    r.raise_for_status()
    j = r.json()
    return {
        "reputation": j.get("ip", {}).get("reputation", "unknown"),
        "confidence": j.get("ip", {}).get("confidence", 0),
        "behaviors":  j.get("behaviors", []),
        "first_seen": j.get("historical", {}).get("first_seen"),
        "last_seen":  j.get("historical", {}).get("last_seen"),
        "seen_by":    j.get("sightings", {}).get("count"),
    }

def otx_ip_lookup(ip, key):
    if not key: return {"skipped": True}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    r = requests.get(url, headers={"X-OTX-API-KEY": key}, timeout=12)
    if r.status_code == 429: return {"rate_limited": True}
    if r.status_code == 401: return {"unauthorized": True}
    r.raise_for_status()
    j = r.json()
    pulses = [
        {"name": p.get("name"), "tags": p.get("tags"), "last_modified": p.get("modified")}
        for p in (j.get("pulse_info", {}).get("pulses") or [])[:5]
    ]
    return {"pulses": pulses, "pulse_count": len(pulses)}

def build_summary(ip: str, keys: Dict[str, str]) -> Dict[str, Any]:
    out = {"ip": ip, "enrichments": {}, "meta": {"queried_at": datetime.now(timezone.utc).isoformat(), "sources": []}}
    def add(name, func):
        try:
            res = func()
            out["enrichments"][name] = res
            out["meta"]["sources"].append(name)
        except requests.HTTPError as e:
            out["enrichments"][name] = {"error": f"HTTP {e.response.status_code}"}
            out["meta"]["sources"].append(name)
        except Exception as e:
            out["enrichments"][name] = {"error": str(e)}
            out["meta"]["sources"].append(name)

    add("ipinfo",    lambda: ipinfo_lookup(ip, keys["ipinfo"]))
    add("abuseipdb", lambda: abuseipdb_lookup(ip, keys.get("abuseipdb","")))
    add("virustotal",lambda: virustotal_ip_lookup(ip, keys.get("virustotal","")))
    add("crowdsec",  lambda: crowdsec_lookup(ip, keys.get("crowdsec","")))
    add("otx",       lambda: otx_ip_lookup(ip, keys.get("otx","")))
    return out

def heuristic_risk_score(summary: Dict[str, Any]) -> Dict[str, Any]:
    e = summary["enrichments"]
    abuse = e.get("abuseipdb", {}) or {}
    vt    = e.get("virustotal", {}) or {}
    cs    = e.get("crowdsec", {}) or {}
    otx   = e.get("otx", {}) or {}

    score_abuse = (abuse.get("abuse_confidence") or 0)/100
    score_vt = min(1.0, ((vt.get("malicious",0) + 0.5*vt.get("suspicious",0))/20))
    score_cs = (cs.get("confidence",0)/100) if (cs.get("reputation")=="malicious") else 0.0
    score_otx = min(1.0, 0.2 * (otx.get("pulse_count") or 0))
    score_recent = 0.6  # 데모 보정

    risk = 100*(0.35*score_abuse + 0.30*score_vt + 0.20*score_cs + 0.10*score_otx + 0.05*score_recent)
    if   risk >= 85: lvl = "critical"
    elif risk >= 70: lvl = "high"
    elif risk >= 40: lvl = "medium"
    else:            lvl = "low"
    return {"risk_numeric": round(risk,1), "risk_level": lvl}

def llm_assess(summary: Dict[str, Any], openai_api_key: str, model: str = "gpt-4o-mini") -> Dict[str, Any]:
    from openai import OpenAI
    client = OpenAI(api_key=openai_api_key)
    e = summary["enrichments"]
    user_text = "IP summary:\n" + json.dumps(e, ensure_ascii=False, indent=2)
    system = """You are a CTI analyst. Return ONLY JSON:
{"risk_level":"low|medium|high|critical","rationale":"<=8 lines","key_findings":[],"recommended_actions":[],"confidence":0.0}"""
    resp = client.chat.completions.create(
        model=model, temperature=0.2, response_format={"type":"json_object"},
        messages=[{"role":"system","content":system},{"role":"user","content":user_text}]
    )
    try:
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return {"risk_level":"unknown","rationale":"LLM parse error","key_findings":[],"recommended_actions":[],"confidence":0.0}

def pretty_print(summary: Dict[str, Any], rule_score: Dict[str, Any], llm_json: Dict[str, Any]):
    ip = summary["ip"]
    info = summary["enrichments"].get("ipinfo", {})
    print("\n================= IP 조사 결과 =================")
    print(f"IP        : {ip}")
    print(f"위치/조직 : {info.get('country')}, {info.get('region')} / {info.get('org')}")
    print(f"Hostname  : {info.get('hostname')}")
    print(f"좌표/TZ   : {info.get('loc')} / {info.get('timezone')}")
    print("-----------------------------------------------")
    for name, data in summary["enrichments"].items():
        print(f"[{name}] -> {json.dumps(data, ensure_ascii=False)[:300]}")
    print("-----------------------------------------------")
    print("룰 기반 점수화:", rule_score)
    print("LLM 평가 JSON :", json.dumps(llm_json, ensure_ascii=False, indent=2))
    rank = {"low":1,"medium":2,"high":3,"critical":4}
    final_level = max([llm_json.get("risk_level","low"), rule_score["risk_level"]], key=lambda k: rank.get(k,0))
    print("===============================================")
    print(f"최종 위험도 : {final_level.upper()}  (룰:{rule_score['risk_level']}, LLM:{llm_json.get('risk_level')})")
    print("권고 조치  :", ", ".join(llm_json.get("recommended_actions", []) or ["차단/모니터링 검토"]))
    print("근거 요약  :", llm_json.get("rationale","-"))
    print("===============================================\n")

def valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text); return True
    except ValueError:
        return False

if __name__ == "__main__":
    missing = [k for k in ["ipinfo","openai"] if not API_KEYS.get(k)]
    if missing:
        print(f"❗ 필수 키 누락: {missing} (ipinfo, openai는 필수)")
    print("IP Agent (종료: q)")
    while True:
        ip = input("조회할 IP를 입력하세요: ").strip()
        if ip.lower() in {"q","quit","exit"}: break
        if not valid_ip(ip):
            print("❗ 올바른 IP가 아닙니다. 예) 8.8.8.8 또는 2001:4860:4860::8888")
            continue
        try:
            summary = build_summary(ip, API_KEYS)
            rule_score = heuristic_risk_score(summary)
            llm_json = llm_assess(summary, API_KEYS["openai"])
            pretty_print(summary, rule_score, llm_json)
        except requests.HTTPError as e:
            print(f"HTTP 오류: {e} / 응답: {e.response.text[:200] if e.response is not None else ''}")
        except Exception as e:
            print(f"오류: {e}")