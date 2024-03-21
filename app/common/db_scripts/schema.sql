CREATE TABLE IF NOT EXISTS "dialog" (
	"ja"	TEXT NOT NULL UNIQUE,
	"npc_name"	TEXT,
	"en"	TEXT,
	PRIMARY KEY("ja")
);

CREATE TABLE IF NOT EXISTS "fixed_dialog_template" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT,
	"bad_string"	INTEGER,
	PRIMARY KEY("ja")
);

CREATE TABLE IF NOT EXISTS "bad_strings" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT,
	PRIMARY KEY("ja")
);

CREATE TABLE IF NOT EXISTS "player" (
	"type"	TEXT NOT NULL,
	"name"	TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS "quests" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT,
	PRIMARY KEY("ja")
);

CREATE TABLE IF NOT EXISTS "story_so_far" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT
);

CREATE TABLE IF NOT EXISTS "story_so_far_template" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT
);

CREATE TABLE IF NOT EXISTS "walkthrough" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT,
	PRIMARY KEY("ja")
);

CREATE TABLE IF NOT EXISTS "m00_strings" (
	"ja"	TEXT NOT NULL UNIQUE,
	"en"	TEXT,
	"file"	TEXT
);

CREATE TABLE IF NOT EXISTS "glossary" (
	"ja"	TEXT,
	"en"	TEXT,
	PRIMARY KEY("ja")
);

CREATE UNIQUE INDEX IF NOT EXISTS "dialog_index" ON "dialog" (
	"ja"
);

CREATE UNIQUE INDEX IF NOT EXISTS "quests_index" ON "quests" (
	"ja"
);

CREATE UNIQUE INDEX IF NOT EXISTS "story_so_far_index" ON "story_so_far" (
	"ja"
);

CREATE UNIQUE INDEX IF NOT EXISTS "walkthrough_index" ON "walkthrough" (
	"ja"
);

CREATE INDEX IF NOT EXISTS "m00_strings_index" ON "m00_strings" (
	"ja"
);

CREATE UNIQUE INDEX IF NOT EXISTS "glossary_index" ON "glossary" (
	"ja"
);

CREATE UNIQUE INDEX IF NOT EXISTS "bad_strings_index" ON "bad_strings" (
	"ja"
);
