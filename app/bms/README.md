# bms

Scripts to use with quickBMS to pull EVT files out for translators to localize.

This is customized for my use and file paths. If you plan on running, you may need to tweak for your own needs.

### Steps

- Open DQX and stay on the announcement screen
- Run `./dump.ps1`
    - `dqx_out` houses all of the EVT files
    - `json_out` is a converstion of EVT -> JSON
    - `new_json` is the new, post-ported JSON files from the old files to the new
        - Review this file and when happy, make this the new `json/_lang` data
    - `bms_hex_dict.csv` is the new hex dictionary
        - Review this file and when happy, make this the new `hex_dict.csv` file
