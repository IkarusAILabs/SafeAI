# Credibility track — study inputs

Inputs for the studies in [`docs/research/CREDIBILITY_TRACK.md`](../../docs/research/CREDIBILITY_TRACK.md)
(roadmap: `ROADMAP.md` §Credibility track). Study *outputs* (scans,
packets, label sheets) are not committed here until a study is published;
`study/`, `labels/`, `review/`, `replay/` and `verify/` working directories are
git-ignored.

| File | Study | Tool |
|---|---|---|
| `targets.yml` | C-2 real-world change study | `scripts/history_study.py` |
| `incidents.yml` | C-3 incident replay (183 candidates, 2026-11-07) | `scripts/incident_search.py` writes it, `scripts/incident_verify.py` records verification, `scripts/incident_replay.py` scores it |
| `target_check.json` | C-2 eligibility facts per target (no findings) and suggested ranges | `scripts/target_check.py` |
| `incident_screening.json` | C-3 selection record: every keyword match and the screen that excluded it | `scripts/incident_search.py` |
| — (pending corpus) | C-1 external review | `scripts/label_kit.py review-packets` |

No tool labels anything: people label, `scripts/label_kit.py` lays out
packets and counts answers (`agreement`, `score`). Rates come with 95%
Wilson intervals and read *insufficient* below 10 labelled units.

The tools clone public repositories with `git`; target code is never
installed or executed (trees are exported with `git archive`), and the
`safeai` scanner gains no network path.

## Quick start

```bash
# C-1: review packets for the 44 pending cases, one sheet per reviewer
python scripts/label_kit.py review-packets --out review/ --reviewers ana,ben
python scripts/label_kit.py agreement review/review-sheet.ana.csv review/review-sheet.ben.csv --field verdict

# C-2: replay confirmed targets, then build blind labelling packets
python scripts/history_study.py --targets research/credibility/targets.yml --out study/
python scripts/label_kit.py packets study/ --out labels/ --labellers ana,ben
python scripts/label_kit.py agreement labels/sheet.ana.csv labels/sheet.ben.csv --field real
python scripts/label_kit.py score study/ labels/adjudicated.csv --json labels/score.json

# C-2: eligibility facts for the owner's confirmation (records no findings)
python scripts/target_check.py --targets research/credibility/targets.yml --out research/credibility/target_check.json

# C-3: verify candidates blind, two people, in the pre-registered order
python scripts/incident_verify.py packets --registry research/credibility/incidents.yml \
    --count 20 --verifiers ana,ben --out verify/
python scripts/incident_verify.py apply --registry research/credibility/incidents.yml \
    verify/sheet.ana.csv verify/sheet.ben.csv

# C-3: re-run the search (keeps verified / rejected entries), validate, replay verified incidents
python scripts/incident_search.py --registry research/credibility/incidents.yml \
    --screening research/credibility/incident_screening.json --existing research/credibility/incidents.yml
python scripts/incident_replay.py --registry research/credibility/incidents.yml --check
python scripts/incident_replay.py --registry research/credibility/incidents.yml --out replay/
```
