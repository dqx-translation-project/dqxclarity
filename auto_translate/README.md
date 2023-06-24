# auto_translate

Uses machine translation to translate all json files found in the `files` directory.

## Setup

- Create a virtual environment:
    - `python -m venv venv`
- Activate your virtual environment
    - `.\venv\Scripts\activate`
- Install requirements
    - `pip install -r requirements.txt`
- Make a copy of the `env` file in this directory and name it `.env`
- Put any json files you want translated into the `files` directory (from weblate's `en` directory)
- Inside of the `.env` file, fill out a list of strings containing your DeepL key(s)
    - Note that the order in which each key is chosen is randomized for each string translated. Helpful when translating multiple files. If you don't want this behavior, just specify a single key
    - example:

```python
DEEPL_KEYS = ["my_key:fx", "my_key2:fx", "my_key3:fx"]
```

- Run the program:
    `python main.py`
