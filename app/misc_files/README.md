## name_overrides.json

This file enables the ability to override both player names and concierge names seen within a MyTown. There is no limit to the number of names you can configure. Each name is imported into the `clarity_dialog.db` database on a launch of the program.

> [!NOTE]
> When removing names from the `player_names` section, to fully remove them from the database, you must have "Disable updates" unchecked in the `dqxclarity` launcher. If launching via cli, you must omit the `-u` flag. This is because we only purge the records in the `glossary` table on an update of the translations.

### player_names

This controls names that you see in the party window (bottom-right portion of the screen), within the system menu and is also what is sent during live translation. If you're looking to "fix" or give yourself a custom name, add your name here.

### mytown_names

This controls the nameplates on the top of a concierge NPC's model when in a MyTown.

Default format:

```json
{
  "player_names": {},
  "mytown_names": {}
}
```

Example usage:

```json
{
  "player_names": {
    "セラニー": "Serany"
  },
  "mytown_names": {
    "セラニーの紹介": "Introducer Serany"
  }
}
