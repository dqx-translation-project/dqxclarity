# json_merge

App written by `HyDE_`. Thanks for making this easy!

Merges existing nested JSON files that previously existed w/ translations into the dumped JSON files from dqxdump.

# How to use

`json-conv.exe -s <src> -d <dst> -o <out>`

```
/src : source json files (flat or nested) with english translations
/dst : destination json files (nested) without english translations
/out : result
```

- Place the original (source) files into the `src` folder.
- Place the dumped (destination) files into the `dst` folder.
- Run `processAll.bat`.
- Merged JSON files will be provided in the `out` folder.
