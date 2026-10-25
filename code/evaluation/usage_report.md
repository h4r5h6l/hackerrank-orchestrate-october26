# Usage Report — Ghost Data Still Exists

## Solution Overview

- **Language**: Python 3.14.4 (stdlib only)
- **Entry point**: `code/main.py`
- **Dependencies**: `csv`, `json`, `os`, `re`, `subprocess`, `datetime`, `collections` (stdlib); `sqlite3` available but not used; `PIL` available but not used (no OCR)
- **External tools**: `pdftotext` for PDF text extraction
- **Model usage**: None — the solution is rule-based and does not call any language model API

## Model Providers and Model Names

| Provider | Model | Usage |
|----------|-------|-------|
| None | N/A | No language model calls made |

The solution uses deterministic rule-based processing rather than LLM-based inference.

## Model-Call Counts

| Metric | Value |
|--------|-------|
| Total model calls | 0 |
| Calls per request | 0 |
| Calls per case | 0 |

## Token Usage

| Metric | Value |
|--------|-------|
| Total input tokens | 0 |
| Total output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0 |
| Average tokens per case | 0 |

## Cost

| Metric | Value |
|--------|-------|
| Estimated total cost | $0.00 |
| Estimated cost per request | $0.00 |
| Estimated cost per case | $0.00 |

## Per-Model Totals

No models used.

## Overall Totals

| Metric | Value |
|--------|-------|
| Total requests processed | 518 |
| Total cases processed | 518 |
| Total model calls | 0 |
| Total tokens | 0 |
| Total cost | $0.00 |
| Average cost per case | $0.00 |

## Processing Details

- **Input file**: `dataset/deletion_requests.csv` (518 rows)
- **Output file**: `output.csv` (518 data rows + header)
- **Evidence files parsed**: 94 manifest entries, 95 files on disk
- **Evidence formats supported**: JSON (.json), SQL (.sql), log (.log), PDF (.pdf via pdftotext), TXT (.txt)
- **Image formats**: PNG (.png) — not processed (no OCR available)
- **Processing time**: Deterministic, single-pass
- **Determinism**: Same input produces same output across runs (sorted by case_id, deterministic JSON serialization)

## Resource Usage

- **Memory**: Minimal — loads all CSVs and evidence into memory (~1944 observations)
- **Disk**: Reads 94 evidence files + 8 CSV files
- **External processes**: One `pdftotext` call per PDF evidence file (4 files)