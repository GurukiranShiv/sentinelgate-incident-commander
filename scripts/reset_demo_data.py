from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
paths = [
    ROOT / 'data' / 'incident_commander.db',
    ROOT / 'data' / 'local_incident_index.jsonl',
]

removed = []
for path in paths:
    if path.exists():
        path.unlink()
        removed.append(str(path.relative_to(ROOT)))

if removed:
    print('Reset complete. Removed:')
    for item in removed:
        print(f'- {item}')
else:
    print('Reset complete. No saved demo data was present.')
