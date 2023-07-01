# scripts

Helpful scripts to run after patches to quickly find common patterns that dqxclarity uses.

### find_names.py

Searches for patterns configured for the `npc_monster_pattern` pattern. Writes the previous 49 bytes of the found string to a file to be used when figuring out the pattern.

```
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python find_names.py --help
```
