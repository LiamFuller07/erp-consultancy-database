#!/usr/bin/env python3
import csv
import json
import re
from datetime import datetime
from pathlib import Path

ROOT = Path('/Users/liam/erp-consultancy-database')
DATA_DIR = ROOT / 'data'
SOURCE_DIR = Path('/Users/liam/Desktop/untitled folder')

CA_FILE = SOURCE_DIR / 'california_erp_consultancies_master - california_erp_consultancies_master.csv (1).csv'
NETSUITE_A = SOURCE_DIR / 'NetSuite_Partners_MASTER - NetSuite_Partners_MASTER.csv (2).csv'
NETSUITE_B = SOURCE_DIR / 'Consultants, NetSuite List - NetSuite_Partners_MASTER (2) (2).csv'
AU_RANKED = SOURCE_DIR / 'ranked_erp_partners.xlsx - Ranked by Size (1).csv'
AU_UPDATED = SOURCE_DIR / 'australian_erp_partners_updated.xlsx - All Partners.csv'

NOW = datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'


def norm_text(value: str) -> str:
    if not value:
        return ''
    value = value.strip().lower()
    value = re.sub(r'\s+', ' ', value)
    return value


def norm_company(value: str) -> str:
    value = norm_text(value)
    value = re.sub(r'[^a-z0-9 ]+', '', value)
    value = re.sub(r'\b(inc|llc|ltd|pty|co|corp|corporation|limited)\b', '', value)
    return re.sub(r'\s+', ' ', value).strip()


def norm_url(value: str) -> str:
    if not value:
        return ''
    value = value.strip()
    value = re.sub(r'^https?://', '', value, flags=re.I)
    value = value.rstrip('/')
    return value.lower()


def split_list(value: str):
    if not value:
        return []
    parts = re.split(r'[;/,]|\s\|\s', value)
    cleaned = [p.strip() for p in parts if p.strip()]
    return cleaned


def merge_fields(base: dict, incoming: dict) -> dict:
    for key, val in incoming.items():
        if key not in base or base[key] in (None, '', [], {}):
            base[key] = val
        elif isinstance(base.get(key), list) and isinstance(val, list):
            merged = base[key] + [v for v in val if v not in base[key]]
            base[key] = merged
        elif key == 'decision_makers' and isinstance(val, list):
            existing = base.get(key, [])
            seen = {(d.get('name','').lower(), d.get('title','').lower()) for d in existing}
            for d in val:
                sig = (d.get('name','').lower(), d.get('title','').lower())
                if sig not in seen:
                    existing.append(d)
                    seen.add(sig)
            base[key] = existing
    return base


def dedupe_key(company, website, city='', state=''):
    name_key = norm_company(company)
    url_key = norm_url(website)
    if url_key:
        return f"{name_key}|{url_key}"
    return f"{name_key}|{norm_text(city)}|{norm_text(state)}"


# --------------------------
# North America
# --------------------------

def load_netsuite_master(path: Path):
    rows = []
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            company = row.get('Company Name', '').strip()
            if not company:
                continue
            rows.append({
                'company_name': company,
                'country': 'USA',
                'city': row.get('Headquarters City', '').strip(),
                'state': row.get('State', '').strip(),
                'employees': row.get('Employee Range', '').strip() or row.get('Employees', '').strip(),
                'erp_systems': ['NetSuite'],
                'key_verticals': split_list(row.get('Key Verticals', '')),
                'awards': row.get('Awards', '').strip(),
                'notable_clients': row.get('Notable Clients', '').strip(),
                'service_focus': row.get('Service Focus', '').strip(),
                'partner_tier': row.get('Partner Tier', '').strip(),
                'partner_status': row.get('Partner Status', '').strip(),
                'netsuite_practice_details': row.get('NetSuite Practice Details', '').strip(),
                'decision_makers': [],
                'priority': 'MEDIUM',
                'data_source': path.name,
            })
    return rows


def load_california(path: Path):
    rows = []
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            company = row.get('Company Name', '').strip()
            if not company:
                continue
            dms = []
            for idx in (1, 2):
                name = row.get(f'Contact {idx} Name', '').strip()
                title = row.get(f'Contact {idx} Title', '').strip()
                link = row.get(f'Contact {idx} LinkedIn', '').strip()
                if name or title or link:
                    dms.append({
                        'name': name,
                        'title': title,
                        'linkedin_url': link,
                    })
            rows.append({
                'company_name': company,
                'country': 'USA',
                'city': row.get('City', '').strip(),
                'state': row.get('Region', '').strip(),
                'employees': row.get('Employees', '').strip(),
                'erp_systems': split_list(row.get('ERP Focus', '')),
                'website': row.get('Website', '').strip(),
                'decision_makers': dms,
                'priority': 'HIGH',
                'data_source': path.name,
            })
    return rows


def build_north_america():
    netsuite_rows = load_netsuite_master(NETSUITE_A)
    netsuite_rows_b = load_netsuite_master(NETSUITE_B)
    california_rows = load_california(CA_FILE)

    # Merge netsuite A/B for field completeness
    ns_map = {}
    for row in netsuite_rows + netsuite_rows_b:
        key = dedupe_key(row['company_name'], row.get('website', ''), row.get('city', ''), row.get('state', ''))
        if key not in ns_map:
            ns_map[key] = row
        else:
            ns_map[key] = merge_fields(ns_map[key], row)

    # Merge California into NetSuite map
    for row in california_rows:
        key = dedupe_key(row['company_name'], row.get('website', ''), row.get('city', ''), row.get('state', ''))
        if key not in ns_map:
            ns_map[key] = row
        else:
            ns_map[key] = merge_fields(ns_map[key], row)
            ns_map[key]['priority'] = 'HIGH'

    # Assign ranks by alphabetical company name
    items = sorted(ns_map.values(), key=lambda r: norm_text(r.get('company_name', '')))
    for i, row in enumerate(items, 1):
        row['id'] = f"na-{i:03d}"
        row['rank'] = i
        row.setdefault('website', '')
        row.setdefault('erp_systems', ['NetSuite'])
        row.setdefault('decision_makers', [])
        row.setdefault('priority', 'MEDIUM')

    return {
        'schema_version': '1.0',
        'region': 'north_america',
        'last_updated': NOW,
        'consultancies': items,
    }


# --------------------------
# Australasia
# --------------------------

def load_au_ranked(path: Path):
    rows = []
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            company = row.get('Company', '').strip()
            if not company:
                continue
            dms = []
            key_exec = row.get('Key Executive', '').strip()
            if key_exec:
                dms.append({
                    'name': key_exec,
                    'title': 'Key Executive',
                    'linkedin_url': row.get('LinkedIn', '').strip(),
                })
            rows.append({
                'company_name': company,
                'country': 'Australia',
                'employees': row.get('Employees/Scale', '').strip(),
                'erp_systems': split_list(row.get('ERP Systems', '')),
                'priority': row.get('Retail Focus', '').strip().upper() or 'MEDIUM',
                'why_target': row.get('Why This Rank', '').strip(),
                'rank': int(row.get('Rank', '0') or 0),
                'decision_makers': dms,
                'data_source': path.name,
            })
    return rows


def load_au_updated(path: Path):
    rows = []
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        for row in reader:
            company = row.get('Company', '').strip()
            if not company:
                continue
            priority_tier = row.get('Priority Tier', '').strip()
            if priority_tier.lower().startswith('tier 1'):
                priority = 'HIGH'
            elif priority_tier.lower().startswith('tier 2'):
                priority = 'MEDIUM'
            elif priority_tier.lower().startswith('tier 3'):
                priority = 'LOWER'
            else:
                priority = 'MEDIUM'
            dms = []
            exec_name = row.get('Executive Name', '').strip()
            if exec_name:
                dms.append({
                    'name': exec_name,
                    'title': row.get('Title', '').strip(),
                    'linkedin_url': row.get('LinkedIn URL', '').strip(),
                })
            rows.append({
                'company_name': company,
                'country': 'Australia',
                'city': row.get('Location', '').strip(),
                'employees': row.get('Employees', '').strip(),
                'erp_systems': split_list(row.get('ERP Systems', '')),
                'priority': priority,
                'awards': row.get('Awards/Notes', '').strip(),
                'retail_focus': row.get('Retail Focus', '').strip(),
                'decision_makers': dms,
                'data_source': path.name,
            })
    return rows


def build_australasia():
    ranked_rows = load_au_ranked(AU_RANKED)
    updated_rows = load_au_updated(AU_UPDATED)

    au_map = {}
    for row in ranked_rows + updated_rows:
        key = dedupe_key(row['company_name'], row.get('website', ''), row.get('city', ''), '')
        if key not in au_map:
            au_map[key] = row
        else:
            au_map[key] = merge_fields(au_map[key], row)

    # Assign ranks if missing: continue after 68
    max_rank = max((r.get('rank', 0) or 0) for r in au_map.values())
    next_rank = max_rank + 1
    for row in au_map.values():
        if not row.get('rank'):
            row['rank'] = next_rank
            next_rank += 1

    items = sorted(au_map.values(), key=lambda r: r.get('rank', 0))
    for i, row in enumerate(items, 1):
        row['id'] = f"au-{i:03d}"
        row.setdefault('priority', 'MEDIUM')
        row.setdefault('decision_makers', [])
        row.setdefault('erp_systems', [])

    return {
        'schema_version': '1.0',
        'region': 'australasia',
        'last_updated': NOW,
        'consultancies': items,
    }


# --------------------------
# Europe (use existing JSON)
# --------------------------

def load_europe_existing():
    # Paste the existing Europe JSON content here if no source file exists.
    europe_path = DATA_DIR / 'europe.json'
    if europe_path.exists():
        return json.loads(europe_path.read_text(encoding='utf-8'))
    raise FileNotFoundError('europe.json not found; provide the existing Europe JSON file.')


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    north_america = build_north_america()
    (DATA_DIR / 'north_america.json').write_text(json.dumps(north_america, indent=2), encoding='utf-8')

    australasia = build_australasia()
    (DATA_DIR / 'australasia.json').write_text(json.dumps(australasia, indent=2), encoding='utf-8')

    # Europe: keep existing JSON (no new source files found)
    europe = load_europe_existing()
    (DATA_DIR / 'europe.json').write_text(json.dumps(europe, indent=2), encoding='utf-8')

    print('Wrote data/australasia.json, data/north_america.json, data/europe.json')


if __name__ == '__main__':
    main()
