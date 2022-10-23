@echo off
for %%f in (src/*.json) do json-conv.exe -s src\%%f -d dst\%%f -o out\%%f
