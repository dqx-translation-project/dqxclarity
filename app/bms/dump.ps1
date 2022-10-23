$DQXPath = "C:\Program Files (x86)\SquareEnix\DRAGON QUEST X\Game\Content"
$OutPath = "dqx_out"

$Folder1000 = "Data"
$Folder2000 = "Ex2000\Data"
$Folder3000 = "Ex3000\Data"
$Folder4000 = "Ex4000\Data"
$Folder5000 = "Ex5000\Data"

# This qbms script can't extract data00040000.
$File1000 = Get-ChildItem -Path "$DQXPath\$Folder1000" -Filter *.idx | Where-Object { $_.Name -NotMatch "data00040000" } | Sort-Object -Descending | ForEach-Object { $_.Name }
$File2000 = Get-ChildItem -Path "$DQXPath\$Folder2000" -Filter *.idx | Sort-Object -Descending | ForEach-Object { $_.Name }
$File3000 = Get-ChildItem -Path "$DQXPath\$Folder3000" -Filter *.idx | Sort-Object -Descending | ForEach-Object { $_.Name }
$File4000 = Get-ChildItem -Path "$DQXPath\$Folder4000" -Filter *.idx | Sort-Object -Descending | ForEach-Object { $_.Name }
$File5000 = Get-ChildItem -Path "$DQXPath\$Folder5000" -Filter *.idx | Sort-Object -Descending | ForEach-Object { $_.Name }

Remove-Item -Recurse -Force $OutPath
New-Item -Path . -Name $OutPath -ItemType "directory" -Force

# Dump evt files
# -. --> Don't terminate if error parsing multiple files
# -K --> Automatically rename existing files
# -Y --> Answer yes to all questions
# -q --> Silent output
# -f --> Specify file ext to dump
ForEach ($idx in $File1000){ & .\quickbms\quickbms.exe -. -K -Y -q -f "{}.evt" dqx.bms "$DQXPath\$Folder1000\$idx" "$OutPath" }
ForEach ($idx in $File2000){ & .\quickbms\quickbms.exe -. -K -Y -q -f "{}.evt" dqx.bms "$DQXPath\$Folder2000\$idx" "$OutPath" }
ForEach ($idx in $File3000){ & .\quickbms\quickbms.exe -. -K -Y -q -f "{}.evt" dqx.bms "$DQXPath\$Folder3000\$idx" "$OutPath" }
ForEach ($idx in $File4000){ & .\quickbms\quickbms.exe -. -K -Y -q -f "{}.evt" dqx.bms "$DQXPath\$Folder4000\$idx" "$OutPath" }
ForEach ($idx in $File5000){ & .\quickbms\quickbms.exe -. -K -Y -q -f "{}.evt" dqx.bms "$DQXPath\$Folder5000\$idx" "$OutPath" }

# Log total files
$TimeStamp = (Get-Date -Format yyyy-MM-dd) + " " + (Get-Date -Format HH:MM:ss)
$DQXVersion = Get-Content "C:\Program Files (x86)\SquareEnix\DRAGON QUEST X\Boot\Boot.ver"
$TimeStamp + " >> " + "DQX Version: $DQXVersion" + " >> " + "Number of EVT files found: " + (Get-ChildItem "$OutPath" | Measure-Object).Count | Out-File -Filepath "bms_out.log" -Append -Force

# Port evt files to json for weblate support
& python port_to_json.py
