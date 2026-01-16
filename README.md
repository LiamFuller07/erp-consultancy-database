# ERP Consultancy Database

Static, local-first AG Grid app for managing ERP consultancies across Australasia, North America, and Europe.

## Structure

- `index.html` - single-page app (AG Grid + charts)
- `data/australasia.json`
- `data/north_america.json`
- `data/europe.json`
- `tools/build_data.py` - rebuilds JSON from local CSV sources

## Build Data

```bash
python3 tools/build_data.py
```

## Run

Open `index.html` in a browser or host the repo via GitHub Pages.

## Data Sources

- `australian_erp_partners_updated.xlsx - All Partners.csv`
- `ranked_erp_partners.xlsx - Ranked by Size (1).csv`
- `california_erp_consultancies_master - california_erp_consultancies_master.csv (1).csv`
- `NetSuite_Partners_MASTER - NetSuite_Partners_MASTER.csv (2).csv`
- `Consultants, NetSuite List - NetSuite_Partners_MASTER (2) (2).csv`
- Europe JSON uses existing dataset (no local CSV found).
