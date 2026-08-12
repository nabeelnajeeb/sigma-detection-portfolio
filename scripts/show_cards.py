import json, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

print(f"Total matches: {len(data)}\n")
for i, entry in enumerate(data):
    ed = entry['document']['data']['Event']['EventData']
    print(f"--- Card {i+1} | {entry.get('name')} ---")
    print('Image:      ', ed.get('Image'))
    print('CommandLine:', ed.get('CommandLine'))
    print('ParentImage:', ed.get('ParentImage'))
    print('User:       ', ed.get('User'))
    print()
