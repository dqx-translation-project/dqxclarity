# auto_translate

Translates a list of files specified in an `.env` file using DeepL.

Supports multiple DeepL keys and randomizes which key to use in the list on each execution.

## Setup

- Create a virtual environment:
    - `python -m venv venv`
- Activate your virtual environment
    - `.\venv\Scripts\activate`
- Install requirements
    - `pip install -r requirements.txt`
- Rename the file in this directory from `env` to `.env`
- Put any json files you want translated into the `files` directory (from weblate's `en` directory)
- Inside of the `.env` file, fill out your DeepL key(s) and a list of files you wish to have translated
    - example:

```python
DEEPL_KEYS = ["my_key:fx", "my_key2:fx", "my_key3:fx"]
FILES_TO_TRANSLATE = ["a_file.json", "b_file.json", "c_file.json"]
```

- Run the program:
    `python main.py`
