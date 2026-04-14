<script>
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { open as openDialog } from "@tauri-apps/plugin-dialog";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { untrack } from "svelte";
  import { THEME_GROUPS, applyTheme } from "$lib/themes.js";

  let { config, onrun } = $props();

  // --- Launcher settings (Tauri owns these) ---
  let nameplates       = $state(untrack(() => config?.launcher?.nameplates       ?? false));
  let updateGameFiles  = $state(untrack(() => config?.launcher?.update_game_files ?? false));
  let disableUpdates   = $state(untrack(() => config?.launcher?.disable_updates   ?? false));
  let debugLogging     = $state(untrack(() => config?.launcher?.debug_logging     ?? false));
  let communityLogging = $state(untrack(() => config?.launcher?.community_logging ?? false));
  let purgeCache       = $state(false); // session-only, never persisted

  // --- Translation settings (Python owns these, we just display/edit) ---
  let useDeepL          = $state(untrack(() => config?.translation?.enabledeepltranslate    ?? false));
  let deepLKey          = $state(untrack(() => config?.translation?.deepltranslatekey        ?? ""));
  let useGoogle         = $state(untrack(() => config?.translation?.enablegoogletranslate    ?? false));
  let googleKey         = $state(untrack(() => config?.translation?.googletranslatekey       ?? ""));
  let useGoogleFree     = $state(untrack(() => config?.translation?.enablegoogletranslatefree ?? false));
  let useCommunityApi   = $state(untrack(() => config?.translation?.enablecommunityapi       ?? false));
  let communityApiKey   = $state(untrack(() => config?.translation?.communityapikey          ?? ""));

  // --- Theme ---
  let selectedTheme = $state(untrack(() => config?.launcher?.theme ?? "rosie"));

  // --- Game tab state ---
  let dqxDir             = $state(untrack(() => config?.config?.installdirectory ?? ""));
  let dqxDirValid        = $state(false);
  let dqxDirError        = $state("");
  let simultaneousLaunch = $state(untrack(() => config?.launcher?.simultaneous_launch ?? false));
  let patching           = $state(false);
  let patchStatus        = $state("");
  let patchIsError       = $state(false);
  let patchProgress      = $state({ downloaded: 0, total: 0 });
  let gameTabInitialized = false;

  // --- UI state ---
  let activeTab = $state("general");
  let statusMsg = $state("");
  let validating = $state(false);
  let hintText = $state("");

  // --- Name overrides state ---
  const OVERRIDES_EXAMPLE =
`{
  "player_names": {
    "セラニー": "Serany"
  },
  "mytown_names": {
    "マイタウン": "My Town"
  }
}`;

  let nameOverridesContent = $state("");
  let nameOverridesLoaded  = false;
  let overridesSaveError   = $state("");
  let overridesSaveSuccess = $state(false);
  let errorRanges          = $state([]);
  let backdropContentEl    = $state(null);

  let highlightedContent = $derived(buildHighlightedContent(nameOverridesContent, errorRanges));

  // --- Database tab state ---
  const DB_ROW_HEIGHT = 29; // px — must match .db-table tbody tr height in CSS
  const DB_OVERSCAN   = 10; // extra rows rendered above/below the viewport

  let dbLoading       = $state(false);
  let dbError         = $state("");
  let dbTables        = $state([]);
  let dbSelectedTable = $state("");
  let dbColumns       = $state([]);
  let dbRows          = $state([]);
  let dbRowCount      = $state(0);
  let dbFilterRaw     = $state("");  // bound to input
  let dbFilter        = $state("");  // debounced
  let dbDeleteConfirm = $state(false);
  let dbScrollTop     = $state(0);
  let dbContainerH    = $state(300);
  let dbContainerEl   = $state(null);

  // Debounce the filter so typing doesn't re-filter 30k rows on every keystroke
  $effect(() => {
    const raw = dbFilterRaw;
    if (!raw.trim()) { dbFilter = ""; return; }
    const t = setTimeout(() => { dbFilter = raw; }, 200);
    return () => clearTimeout(t);
  });

  // Reset scroll when the active filter or table changes
  $effect(() => {
    dbFilter; dbSelectedTable;
    if (dbContainerEl) dbContainerEl.scrollTop = 0;
    dbScrollTop = 0;
  });

  let dbFilteredRows = $derived(
    dbFilter.trim()
      ? dbRows.filter(row =>
          row.values.some(v => v != null && v.toLowerCase().includes(dbFilter.toLowerCase()))
        )
      : dbRows
  );
  let dbSelectedCount      = $derived(dbRows.filter(r => r.selected).length);
  let dbAllVisibleSelected = $derived(
    dbFilteredRows.length > 0 && dbFilteredRows.every(r => r.selected)
  );

  // Virtual scroll: only render the slice of rows visible in the viewport
  let dbVirtStart  = $derived(Math.max(0, Math.floor(dbScrollTop / DB_ROW_HEIGHT) - DB_OVERSCAN));
  let dbVirtEnd    = $derived(Math.min(dbFilteredRows.length, Math.ceil((dbScrollTop + dbContainerH) / DB_ROW_HEIGHT) + DB_OVERSCAN));
  let dbVisibleRows = $derived(dbFilteredRows.slice(dbVirtStart, dbVirtEnd));
  let dbTopPad     = $derived(dbVirtStart * DB_ROW_HEIGHT);
  let dbBottomPad  = $derived(Math.max(0, (dbFilteredRows.length - dbVirtEnd) * DB_ROW_HEIGHT));

  // ── Name-overrides helpers ────────────────────────────────────────────────

  function escapeHtml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  function buildHighlightedContent(text, ranges) {
    if (!ranges.length) return escapeHtml(text) + "\n";
    const sorted = [...ranges].sort((a, b) => a.start - b.start);
    let html = "";
    let pos = 0;
    for (const { start, end } of sorted) {
      const s = Math.max(pos, 0);
      const e = Math.min(end, text.length);
      if (start > s) html += escapeHtml(text.slice(s, start));
      html += `<mark class="err-mark">${escapeHtml(text.slice(start, e))}</mark>`;
      pos = e;
    }
    if (pos < text.length) html += escapeHtml(text.slice(pos));
    return html + "\n";
  }

  function getJsonSyntaxRanges(text, error) {
    const m = (error.message || "").match(/at position (\d+)/i);
    if (!m) return [];
    const pos = Math.min(parseInt(m[1]), text.length);
    const lineEnd = text.indexOf("\n", pos);
    return [{ start: pos, end: lineEnd === -1 ? text.length : lineEnd }];
  }

  function findKeyRanges(text, key) {
    const idx = text.indexOf(`"${key}"`);
    if (idx === -1) return [];
    const lineEnd = text.indexOf("\n", idx);
    return [{ start: idx, end: lineEnd === -1 ? text.length : lineEnd }];
  }

  function validateOverridesSchema(obj, text) {
    const errors = [];
    if (typeof obj !== "object" || Array.isArray(obj) || obj === null) {
      errors.push({ message: "Root value must be an object", ranges: [] });
      return errors;
    }
    for (const key of ["player_names", "mytown_names"]) {
      if (!(key in obj)) {
        errors.push({ message: `Missing required key: "${key}"`, ranges: [] });
      } else if (typeof obj[key] !== "object" || Array.isArray(obj[key]) || obj[key] === null) {
        errors.push({ message: `"${key}" must be an object`, ranges: findKeyRanges(text, key) });
      }
    }
    return errors;
  }

  async function openNameOverridesTab() {
    activeTab = "nameoverrides";
    if (!nameOverridesLoaded) {
      nameOverridesLoaded = true;
      nameOverridesContent = await invoke("read_name_overrides").catch(
        () => "misc_files/name_overrides.json not found"
      );
    }
  }

  function clearOverridesErrors() {
    errorRanges = [];
    overridesSaveError = "";
  }

  function syncScroll(e) {
    if (backdropContentEl) {
      backdropContentEl.style.transform =
        `translate(${-e.target.scrollLeft}px, ${-e.target.scrollTop}px)`;
    }
  }

  async function saveNameOverrides() {
    overridesSaveError = "";
    overridesSaveSuccess = false;
    errorRanges = [];

    let parsed;
    try {
      parsed = JSON.parse(nameOverridesContent);
    } catch (e) {
      overridesSaveError = `Save failed: invalid JSON — ${e.message}`;
      errorRanges = getJsonSyntaxRanges(nameOverridesContent, e);
      return;
    }

    const schemaErrors = validateOverridesSchema(parsed, nameOverridesContent);
    if (schemaErrors.length > 0) {
      overridesSaveError = `Save failed: ${schemaErrors.map(e => e.message).join("; ")}`;
      errorRanges = schemaErrors.flatMap(e => e.ranges);
      return;
    }

    try {
      const pretty = JSON.stringify(parsed, null, 2);
      await invoke("save_name_overrides", { content: pretty });
      nameOverridesContent = pretty;
      overridesSaveSuccess = true;
      setTimeout(() => { overridesSaveSuccess = false; }, 2000);
    } catch (e) {
      overridesSaveError = `Save failed: ${e}`;
    }
  }

  // ── Database tab helpers ──────────────────────────────────────────────────

  async function readDatabase() {
    dbLoading = true;
    dbError = "";
    dbTables = [];
    dbSelectedTable = "";
    dbColumns = [];
    dbRows = [];
    dbRowCount = 0;
    dbFilterRaw = "";
    try {
      dbTables = await invoke("read_db_tables");
    } catch (e) {
      dbError = typeof e === "string" ? e : "Failed to read database.";
    }
    dbLoading = false;
  }

  async function loadDbTable(table) {
    if (!table) return;
    dbSelectedTable = table;
    dbFilterRaw = "";
    dbColumns = [];
    dbRows = [];
    dbRowCount = 0;
    dbLoading = true;
    try {
      const data = await invoke("read_db_table", { table });
      dbColumns = data.columns;
      dbRows = data.rows.map(r => ({ ...r, selected: false }));
      dbRowCount = dbRows.length;
    } catch (e) {
      dbError = typeof e === "string" ? e : "Failed to load table.";
    }
    dbLoading = false;
  }

  function toggleDbRow(rowid) {
    dbRows = dbRows.map(r => r.rowid === rowid ? { ...r, selected: !r.selected } : r);
  }

  function toggleDbSelectAll() {
    const ids = new Set(dbFilteredRows.map(r => r.rowid));
    const allSel = dbFilteredRows.every(r => r.selected);
    dbRows = dbRows.map(r => ids.has(r.rowid) ? { ...r, selected: !allSel } : r);
  }

  function initiateDelete() {
    if (dbSelectedCount === 0) return;
    dbDeleteConfirm = true;
  }

  async function confirmDbDelete() {
    dbDeleteConfirm = false;
    const rowids = dbRows.filter(r => r.selected).map(r => r.rowid);
    try {
      await invoke("delete_db_rows", { table: dbSelectedTable, rowids });
      dbRows = dbRows.filter(r => !r.selected);
    } catch (e) {
      dbError = typeof e === "string" ? e : "Failed to delete rows.";
    }
  }

  function selectCellText(e) {
    const range = document.createRange();
    range.selectNodeContents(e.currentTarget);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }

  // ── General / Advanced tab logic ──────────────────────────────────────────

  function selectDeepL()      { useDeepL = true;  useGoogle = false; useGoogleFree = false; }
  function selectGoogle()     { useDeepL = false; useGoogle = true;  useGoogleFree = false; }
  function selectGoogleFree() { useDeepL = false; useGoogle = false; useGoogleFree = true;  }
  function clearTranslation() { useDeepL = false; useGoogle = false; useGoogleFree = false; }

  function toggleDeepL()      { if (useDeepL)      clearTranslation(); else selectDeepL();      }
  function toggleGoogle()     { if (useGoogle)     clearTranslation(); else selectGoogle();     }
  function toggleGoogleFree() { if (useGoogleFree) clearTranslation(); else selectGoogleFree(); }

  function communityLoggingChanged() {
    if (communityLogging) {
      const ok = confirm(
        "You have enabled community logging.\n\n" +
        "This feature is unstable and may result in unexpected behavior while playing, " +
        "up to and including crashes. Do not report issues of crashing if you have this enabled.\n\n" +
        "Do you still want to enable this to help with the project?"
      );
      if (!ok) communityLogging = false;
    }
  }

  function purgeCacheChanged() {
    if (purgeCache) {
      const ok = confirm(
        "Purge Database Cache will delete all cached translations from your local database.\n\n" +
        "This cannot be undone. Continue?"
      );
      if (!ok) purgeCache = false;
    }
  }

  async function validateKey() {
    validating = true;
    statusMsg = "Validating…";
    try {
      if (useDeepL) {
        statusMsg = await invoke("validate_deepl_key", { key: deepLKey });
      } else if (useGoogle) {
        statusMsg = await invoke("validate_google_key", { key: googleKey });
      } else {
        statusMsg = "Enable an API service before validating.";
      }
    } catch (e) {
      statusMsg = typeof e === "string" ? e : "Validation failed.";
    }
    validating = false;
  }

  async function run() {
    await invoke("save_config", {
      launcher: {
        nameplates,
        update_game_files: updateGameFiles,
        disable_updates: disableUpdates,
        debug_logging: debugLogging,
        community_logging: communityLogging,
        simultaneous_launch: simultaneousLaunch,
        theme: selectedTheme,
      },
      translation: {
        enabledeepltranslate:      useDeepL,
        deepltranslatekey:         deepLKey,
        enablegoogletranslate:     useGoogle,
        googletranslatekey:        googleKey,
        enablegoogletranslatefree: useGoogleFree,
        enablecommunityapi:        useCommunityApi,
        communityapikey:           communityApiKey,
      },
    });

    const args = [];
    if (nameplates)       args.push("--nameplates");
    if (updateGameFiles)  args.push("--update-dat");
    if (disableUpdates)   args.push("--disable-update-check");
    if (debugLogging)     args.push("--debug");
    if (communityLogging) args.push("--community-logging");
    if (purgeCache)       args.push("--purge-cache");
    if (useDeepL || useGoogle || useGoogleFree) args.push("--communication-window");

    if (simultaneousLaunch && dqxDir) {
      invoke("launch_dqx", { installDir: dqxDir }).catch(() => {});
    }

    onrun(args);
  }

  // Silently validate the saved DQX dir the first time the Game tab is opened
  $effect(() => {
    if (activeTab === "game" && !gameTabInitialized) {
      gameTabInitialized = true;
      if (dqxDir) {
        invoke("validate_dqx_dir", { dir: dqxDir })
          .then(() => { dqxDirValid = true; })
          .catch(() => { dqxDirValid = false; });
      }
    }
  });

  async function browseDqxDir() {
    const selected = await openDialog({ directory: true, multiple: false, title: "Select DQX Installation Folder" });
    if (!selected) return;
    dqxDirError = "";
    dqxDirValid = false;
    try {
      await invoke("validate_dqx_dir", { dir: selected });
      dqxDir = selected;
      dqxDirValid = true;
      await invoke("save_game_dir", { dir: selected });
    } catch (e) {
      dqxDir = selected;
      dqxDirError = typeof e === "string" ? e : "Could not find DQX game files in the selected folder.";
    }
  }

  async function openDqx() {
    try {
      await invoke("launch_dqx", { installDir: dqxDir });
    } catch (e) {
      dqxDirError = typeof e === "string" ? e : "Failed to launch DQX.";
    }
  }

  async function openDqxConfig() {
    try {
      await invoke("launch_dqx_config", { installDir: dqxDir });
    } catch (e) {
      dqxDirError = typeof e === "string" ? e : "Failed to launch DQXConfig.";
    }
  }

  async function runPatch(cmd) {
    patching = true;
    patchStatus = "";
    patchIsError = false;
    patchProgress = { downloaded: 0, total: 0 };

    let unlisten;
    try {
      unlisten = await listen("patch-progress", (event) => {
        patchProgress = event.payload;
      });
      await invoke(cmd, { installDir: dqxDir });
      patchStatus = "Done!";
      setTimeout(() => { patchStatus = ""; }, 3000);
    } catch (e) {
      patchStatus = typeof e === "string" ? e : "Operation failed.";
      patchIsError = true;
    } finally {
      unlisten?.();
      patching = false;
    }
  }

  function patchLauncher()   { runPatch("patch_launcher");   }
  function restoreLauncher() { runPatch("restore_launcher"); }
  function patchConfig()     { runPatch("patch_config");     }
  function restoreConfig()   { runPatch("restore_config");   }

  function openGitHub() {
    openUrl("https://github.com/dqx-translation-project/dqxclarity");
  }
</script>

<div class="settings">
  <div class="sidebar">
    <select
      class="theme-select"
      bind:value={selectedTheme}
      onchange={() => {
        applyTheme(selectedTheme);
        invoke("save_theme", { theme: selectedTheme }).catch(() => {});
      }}
    >
      {#each THEME_GROUPS as group}
        <optgroup label={group.label}>
          {#each group.themes as t}
            <option value={t.id}>{t.label}</option>
          {/each}
        </optgroup>
      {/each}
    </select>
    <img src="/characters/Rosie.png" alt="Rosie" class="mascot" />
  </div>

  <div class="content">
    <!-- Tabs -->
    <div class="tabs">
      <button class:active={activeTab === "general"}       onclick={() => activeTab = "general"}>General</button>
      <button class:active={activeTab === "advanced"}      onclick={() => activeTab = "advanced"}>Advanced</button>
      <button class:active={activeTab === "nameoverrides"} onclick={openNameOverridesTab}>Name Overrides</button>
      <button class:active={activeTab === "database"}      onclick={() => activeTab = "database"}>Database</button>
      <button class:active={activeTab === "game"}          onclick={() => activeTab = "game"}>Game</button>
    </div>

    <!-- General tab -->
    {#if activeTab === "general"}
      <div class="tab-content">
        <fieldset>
          <legend>Configuration</legend>
          <label
            onmouseenter={() => hintText = "Transliterates Japanese nameplates to English."}
            onmouseleave={() => hintText = ""}
          ><input type="checkbox" bind:checked={nameplates} />Nameplates</label>
          <label
            onmouseenter={() => hintText = "Downloads/updates the modded DAT/IDX files."}
            onmouseleave={() => hintText = ""}
          ><input type="checkbox" bind:checked={updateGameFiles} />Update Game Files</label>
          <label
            onmouseenter={() => hintText = "Don't check for dqxclarity updates on launch."}
            onmouseleave={() => hintText = ""}
          ><input type="checkbox" bind:checked={disableUpdates} />Disable Updates</label>
          <label
            onmouseenter={() => hintText = "Enables more verbose logging."}
            onmouseleave={() => hintText = ""}
          ><input type="checkbox" bind:checked={debugLogging} />Enable Debug Logging</label>
        </fieldset>

        <fieldset>
          <legend>API Settings</legend>

          <div class="api-row">
            <label class="api-toggle"
              onmouseenter={() => hintText = "Enable DeepL as your choice of external translation."}
              onmouseleave={() => hintText = ""}
            >
              <input type="checkbox" checked={useDeepL} onchange={toggleDeepL} />
              DeepL
            </label>
            <input
              type="password"
              class="api-key"
              placeholder="DeepL auth key"
              bind:value={deepLKey}
              disabled={!useDeepL}
              onmouseenter={() => hintText = "Paste your DeepL API Key here."}
              onmouseleave={() => hintText = ""}
            />
          </div>

          <div class="api-row">
            <label class="api-toggle"
              onmouseenter={() => hintText = "Enable Google Translate as your choice of external translation."}
              onmouseleave={() => hintText = ""}
            >
              <input type="checkbox" checked={useGoogle} onchange={toggleGoogle} />
              Google Translate
            </label>
            <input
              type="password"
              class="api-key"
              placeholder="Google API key"
              bind:value={googleKey}
              disabled={!useGoogle}
              onmouseenter={() => hintText = "Paste your Google Translate API Key here."}
              onmouseleave={() => hintText = ""}
            />
          </div>

          <div class="api-row">
            <label class="api-toggle"
              onmouseenter={() => hintText = "Uses the 'free' version of Google Translate. Rate limiting may ensue under use."}
              onmouseleave={() => hintText = ""}
            >
              <input type="checkbox" checked={useGoogleFree} onchange={toggleGoogleFree} />
              Free Google Translate
            </label>
          </div>

          <div class="validate-row">
            <button
              onclick={validateKey}
              disabled={validating || (!useDeepL && !useGoogle)}
              onmouseenter={() => hintText = "Validate that the selected API key works. Check here for status."}
              onmouseleave={() => hintText = ""}
            >
              {validating ? "Validating…" : "Validate Enabled Key"}
            </button>
            {#if statusMsg}
              <span class="status-msg">{statusMsg}</span>
            {/if}
          </div>
        </fieldset>
      </div>
    {/if}

    <!-- Advanced tab -->
    {#if activeTab === "advanced"}
      <div class="tab-content">
        <fieldset>
          <legend>Configuration</legend>
          <label
            onmouseenter={() => hintText = "Enables logging of internal game files to a text file."}
            onmouseleave={() => hintText = ""}
          >
            <input type="checkbox" bind:checked={communityLogging} onchange={communityLoggingChanged} />
            Community Logging
          </label>
          <label
            onmouseenter={() => hintText = "Deletes all cached translations from your local database."}
            onmouseleave={() => hintText = ""}
          >
            <input type="checkbox" bind:checked={purgeCache} onchange={purgeCacheChanged} />
            Purge Database Cache
          </label>
        </fieldset>

        <fieldset>
          <legend>API Settings</legend>
          <div class="api-row">
            <label class="api-toggle"
              onmouseenter={() => hintText = "Enable Community Api for submitting game strings to devs."}
              onmouseleave={() => hintText = ""}
            >
              <input type="checkbox" bind:checked={useCommunityApi} />
              Community API
            </label>
            <input
              type="password"
              class="api-key"
              placeholder="Community API key"
              bind:value={communityApiKey}
              disabled={!useCommunityApi}
              onmouseenter={() => hintText = "Paste your Community API Key here."}
              onmouseleave={() => hintText = ""}
            />
          </div>
        </fieldset>
      </div>
    {/if}

    <!-- Name Overrides tab -->
    {#if activeTab === "nameoverrides"}
      <div class="tab-content overrides-content">
        {#if overridesSaveError}
          <div class="overrides-msg overrides-msg--error">{overridesSaveError}</div>
        {:else if overridesSaveSuccess}
          <div class="overrides-msg overrides-msg--success">Saved!</div>
        {/if}

        <div class="editor-split">
          <div class="editor-pane">
            <div class="editor-wrapper">
              <div class="backdrop">
                <div class="backdrop-content" bind:this={backdropContentEl}>{@html highlightedContent}</div>
              </div>
              <textarea
                class="editor-textarea"
                bind:value={nameOverridesContent}
                oninput={clearOverridesErrors}
                onscroll={syncScroll}
                spellcheck={false}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
              ></textarea>
            </div>
          </div>

          <div class="example-pane">
            <div class="example-label">Example</div>
            <pre class="example-content">{OVERRIDES_EXAMPLE}</pre>
          </div>
        </div>

        <div class="overrides-actions">
          <span class="overrides-desc">Override Japanese player and MyTown names with your own custom names.</span>
          <button
            class="btn-save"
            onclick={saveNameOverrides}
            onmouseenter={() => hintText = "Save changes to name_overrides.json."}
            onmouseleave={() => hintText = ""}
          >Save</button>
        </div>
      </div>
    {/if}

    <!-- Database tab -->
    {#if activeTab === "database"}
      <div class="tab-content db-content">

        <!-- Toolbar row 1: load controls -->
        <div class="db-toolbar">
          <button class="db-btn" onclick={readDatabase} disabled={dbLoading}>
            {dbLoading ? "Loading…" : "Read Database"}
          </button>

          {#if dbTables.length > 0}
            <select
              class="db-select"
              value={dbSelectedTable}
              onchange={(e) => loadDbTable(e.currentTarget.value)}
            >
              <option value="" disabled>Select table…</option>
              {#each dbTables as t}
                <option value={t}>{t}</option>
              {/each}
            </select>
          {/if}
        </div>

        <!-- Toolbar row 2: filter + delete (always reserved so they're never pushed off-screen) -->
        <div class="db-toolbar2">
          <input
            class="db-filter"
            placeholder="Filter rows…"
            bind:value={dbFilterRaw}
            disabled={dbColumns.length === 0}
          />
          <button
            class="db-btn db-btn--danger"
            onclick={initiateDelete}
            disabled={dbSelectedCount === 0}
          >
            Delete{dbSelectedCount > 0 ? ` (${dbSelectedCount})` : ""}
          </button>
        </div>

        {#if dbError}
          <div class="db-error">{dbError}</div>
        {/if}

        <!-- Table -->
        {#if dbColumns.length > 0}
          <div
            class="db-table-wrap"
            bind:this={dbContainerEl}
            bind:clientHeight={dbContainerH}
            onscroll={(e) => { dbScrollTop = e.currentTarget.scrollTop; }}
          >
            <table class="db-table">
              <thead>
                <tr>
                  <th class="col-check">
                    <input
                      type="checkbox"
                      checked={dbAllVisibleSelected}
                      onchange={toggleDbSelectAll}
                    />
                  </th>
                  {#each dbColumns as col}
                    <th>{col}</th>
                  {/each}
                </tr>
              </thead>
              <tbody>
                {#if dbTopPad > 0}
                  <tr class="virt-spacer" style="height:{dbTopPad}px">
                    <td colspan={dbColumns.length + 1}></td>
                  </tr>
                {/if}
                {#each dbVisibleRows as row (row.rowid)}
                  <tr class:row-selected={row.selected}>
                    <td class="col-check">
                      <input
                        type="checkbox"
                        checked={row.selected}
                        onchange={() => toggleDbRow(row.rowid)}
                      />
                    </td>
                    {#each row.values as val}
                      <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_noninteractive_element_interactions -->
                      <td onclick={selectCellText} title={val ?? ""}>{val ?? ""}</td>
                    {/each}
                  </tr>
                {/each}
                {#if dbBottomPad > 0}
                  <tr class="virt-spacer" style="height:{dbBottomPad}px">
                    <td colspan={dbColumns.length + 1}></td>
                  </tr>
                {/if}
                {#if dbFilteredRows.length === 0}
                  <tr>
                    <td colspan={dbColumns.length + 1} class="db-empty">No rows match the filter.</td>
                  </tr>
                {/if}
              </tbody>
            </table>
          </div>
        {/if}

        {#if dbRowCount > 0}
          <div class="db-row-count">{dbRowCount.toLocaleString()} rows read</div>
        {/if}

      </div>
    {/if}

    <!-- Game tab -->
    {#if activeTab === "game"}
      <div class="tab-content">
        <fieldset>
          <legend>Installation</legend>
          <div class="game-dir-row">
            <input
              type="text"
              class="game-dir-input"
              value={dqxDir}
              readonly
              placeholder="No folder selected"
              onmouseenter={() => hintText = "Path to your DQX installation folder."}
              onmouseleave={() => hintText = ""}
            />
            <button
              class="db-btn"
              onclick={browseDqxDir}
              onmouseenter={() => hintText = "Browse for your DQX installation folder."}
              onmouseleave={() => hintText = ""}
            >Browse...</button>
          </div>
          {#if dqxDirError}
            <div class="game-dir-error">{dqxDirError}</div>
          {/if}
        </fieldset>

        {#if dqxDirValid}
          <fieldset>
            <legend>Launch</legend>
            <div class="game-launch-row">
              <button
                class="db-btn"
                onclick={openDqx}
                onmouseenter={() => hintText = "Launch DQXBoot.exe."}
                onmouseleave={() => hintText = ""}
              >Open DQX</button>
              <button
                class="db-btn"
                onclick={openDqxConfig}
                onmouseenter={() => hintText = "Launch DQXConfig.exe."}
                onmouseleave={() => hintText = ""}
              >Open DQXConfig</button>
            </div>
            <label
              onmouseenter={() => hintText = "When Run is clicked, launch DQX and dqxclarity at the same time."}
              onmouseleave={() => hintText = ""}
            >
              <input type="checkbox" bind:checked={simultaneousLaunch} />
              Launch both DQX and dqxclarity together
            </label>
          </fieldset>

          <fieldset>
            <legend>Patches</legend>
            <p class="patch-note">Downloads executables from GitHub.</p>
            <div class="patch-grid">
              <button
                class="db-btn"
                onclick={patchLauncher}
                disabled={patching}
                onmouseenter={() => hintText = "Patch the Japanese launcher with an English version."}
                onmouseleave={() => hintText = ""}
              >Patch Launcher</button>
              <button
                class="db-btn"
                onclick={restoreLauncher}
                disabled={patching}
                onmouseenter={() => hintText = "Restore the original Japanese launcher executable."}
                onmouseleave={() => hintText = ""}
              >Restore Launcher</button>
              <button
                class="db-btn"
                onclick={patchConfig}
                disabled={patching}
                onmouseenter={() => hintText = "Patch the Japanese Config with an English version."}
                onmouseleave={() => hintText = ""}
              >Patch Config</button>
              <button
                class="db-btn"
                onclick={restoreConfig}
                disabled={patching}
                onmouseenter={() => hintText = "Restore the original Japanese Config executable."}
                onmouseleave={() => hintText = ""}
              >Restore Config</button>
            </div>
            {#if patching}
              <div class="patch-bar-track">
                {#if patchProgress.total > 0}
                  <div class="patch-bar-fill" style="width:{Math.min(100, Math.round(patchProgress.downloaded / patchProgress.total * 100))}%"></div>
                {:else}
                  <div class="patch-bar-fill patch-bar-fill--indeterminate"></div>
                {/if}
              </div>
            {/if}
            {#if patchStatus}
              <div class="patch-status" class:patch-status--error={patchIsError}>{patchStatus}</div>
            {/if}
          </fieldset>
        {/if}
      </div>
    {/if}

    <!-- Hint bar -->
    <div class="hint-bar">{hintText || "\u00a0"}</div>

    <!-- Action buttons -->
    <div class="actions">
      <button
        class="btn-secondary"
        onclick={openGitHub}
        onmouseenter={() => hintText = "View the source code in your default browser."}
        onmouseleave={() => hintText = ""}
      >GitHub</button>
      <button
        class="btn-primary"
        onclick={run}
        onmouseenter={() => hintText = "Run the program."}
        onmouseleave={() => hintText = ""}
      >Run</button>
    </div>
  </div>
</div>

<!-- Delete confirmation dialog -->
{#if dbDeleteConfirm}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="confirm-overlay" role="presentation" onclick={() => dbDeleteConfirm = false}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="confirm-box" role="dialog" aria-modal="true" onclick={(e) => e.stopPropagation()}>
      <p>Are you sure you want to delete {dbSelectedCount} row{dbSelectedCount !== 1 ? "s" : ""}?</p>
      <div class="confirm-actions">
        <button onclick={() => dbDeleteConfirm = false}>No</button>
        <button class="db-btn--danger-solid" onclick={confirmDbDelete}>Yes</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .settings {
    display: flex;
    height: 100%;
  }

  .sidebar {
    width: 130px;
    background: var(--surface2);
    display: flex;
    flex-direction: column;
    align-items: center;
    padding-top: 0.7rem;
    flex-shrink: 0;
  }

  .theme-select {
    width: 110px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    font-size: 0.75rem;
    padding: 0.22rem 0.3rem;
    cursor: pointer;
    outline: none;
    flex-shrink: 0;
  }

  .theme-select:hover,
  .theme-select:focus {
    border-color: var(--muted);
  }

  .mascot {
    width: 110px;
    height: auto;
    object-fit: contain;
    margin-top: auto;
    margin-bottom: auto;
  }

  .content {
    flex: 1;
    min-width: 0; /* prevent flex blowout when table columns are wide */
    display: flex;
    flex-direction: column;
    padding: 1rem 1.2rem;
    gap: 0.6rem;
    min-height: 0;
  }

  /* ── Tabs ─────────────────────────────────────────────────────────────── */

  .tabs {
    display: flex;
    gap: 2px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.4rem;
    flex-shrink: 0;
  }

  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 0.35rem 0.9rem;
    cursor: pointer;
    font-size: 0.85rem;
    color: var(--muted);
    margin-bottom: -1px;
  }

  .tabs button.active {
    color: var(--text);
    border-bottom-color: var(--accent);
  }

  /* ── Shared tab-content ──────────────────────────────────────────────── */

  .tab-content {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    flex: 1;
    min-height: 0;
  }

  fieldset {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.6rem 0.8rem;
    margin: 0;
  }

  legend {
    font-size: 0.75rem;
    color: var(--muted);
    padding: 0 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  label {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.875rem;
    padding: 0.18rem 0;
    cursor: pointer;
    user-select: none;
  }

  input[type="checkbox"] {
    accent-color: var(--accent);
    width: 15px;
    height: 15px;
  }

  .api-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.18rem 0;
  }

  .api-toggle { min-width: 160px; flex-shrink: 0; }

  .api-key {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.5rem;
    font-size: 0.8rem;
    color: var(--text);
    min-width: 0;
  }

  .api-key:disabled { opacity: 0.4; cursor: not-allowed; }

  .validate-row {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    margin-top: 0.4rem;
  }

  .validate-row button {
    font-size: 0.8rem;
    padding: 0.3rem 0.7rem;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    cursor: pointer;
    white-space: nowrap;
  }

  .validate-row button:disabled { opacity: 0.4; cursor: not-allowed; }

  .status-msg { font-size: 0.78rem; color: var(--muted); }

  /* ── Name Overrides tab ──────────────────────────────────────────────── */

  .overrides-content { gap: 0.5rem; }

  .overrides-msg {
    font-size: 0.78rem;
    padding: 0.3rem 0.5rem;
    border-radius: 4px;
    flex-shrink: 0;
  }

  .overrides-msg--error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--danger) 30%, transparent);
  }

  .overrides-msg--success {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--success) 30%, transparent);
  }

  .editor-split {
    display: flex;
    flex: 1;
    min-height: 0;
    gap: 0.6rem;
  }

  .editor-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
  }

  .example-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    min-height: 0;
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--surface);
    overflow: hidden;
  }

  .example-label {
    font-size: 0.72rem;
    color: var(--muted);
    padding: 0.25rem 0.5rem;
    border-bottom: 1px solid var(--border);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    flex-shrink: 0;
  }

  .example-content {
    flex: 1;
    overflow: auto;
    margin: 0;
    padding: 0.4rem 0.5rem;
    font-family: "Cascadia Code", Consolas, "Courier New", monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    color: var(--muted);
    white-space: pre;
    user-select: none;
  }

  .editor-wrapper {
    position: relative;
    flex: 1;
    min-height: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  .editor-wrapper:focus-within { border-color: var(--muted); }

  .backdrop {
    position: absolute;
    inset: 0;
    overflow: hidden;
    pointer-events: none;
    border-radius: 4px;
  }

  .backdrop-content {
    font-family: "Cascadia Code", Consolas, "Courier New", monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    padding: 0.4rem 0.5rem;
    white-space: pre-wrap;
    overflow-wrap: break-word;
    word-break: break-all;
    color: transparent;
  }

  :global(.err-mark) {
    background: transparent;
    color: transparent;
    text-decoration: underline wavy var(--danger);
  }

  .editor-textarea {
    display: block;
    position: relative;
    z-index: 1;
    width: 100%;
    height: 100%;
    resize: none;
    background: transparent;
    border: none;
    border-radius: 4px;
    outline: none;
    padding: 0.4rem 0.5rem;
    font-family: "Cascadia Code", Consolas, "Courier New", monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    color: var(--text);
    caret-color: var(--text);
  }

  .overrides-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }

  .overrides-desc { font-size: 0.75rem; color: var(--muted); }

  .btn-save {
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 1rem;
    font-size: 0.85rem;
    cursor: pointer;
  }

  .btn-save:hover { filter: brightness(1.1); }

  /* ── Database tab ────────────────────────────────────────────────────── */

  .db-content { gap: 0.4rem; }

  .db-toolbar,
  .db-toolbar2 {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-shrink: 0;
  }

  .db-btn {
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.28rem 0.75rem;
    font-size: 0.82rem;
    cursor: pointer;
    white-space: nowrap;
  }

  .db-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .db-btn:not(:disabled):hover { filter: brightness(1.1); }

  .db-btn--danger {
    color: var(--danger);
    border-color: var(--danger);
    background: transparent;
  }

  .db-btn--danger:disabled { opacity: 0.35; }

  .db-select {
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.28rem 0.5rem;
    font-size: 0.82rem;
    cursor: pointer;
  }

  .db-filter {
    flex: 1; /* fill remaining space in toolbar row 2 */
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.28rem 0.5rem;
    font-size: 0.82rem;
    min-width: 0;
  }

  .db-filter:focus { outline: none; border-color: var(--muted); }

  .db-error {
    font-size: 0.78rem;
    color: var(--danger);
    flex-shrink: 0;
  }

  .db-table-wrap {
    flex: 1;
    min-height: 0;
    min-width: 0;
    overflow: auto; /* scrolls both axes when table is wider than the pane */
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  .db-table {
    border-collapse: collapse;
    width: 100%;
    font-size: 0.78rem;
  }

  .db-table th {
    position: sticky;
    top: 0;
    background: var(--surface2);
    padding: 0.32rem 0.6rem;
    text-align: left;
    font-size: 0.73rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
    border-bottom: 1px solid var(--border);
    z-index: 1;
  }

  .db-table td {
    padding: 0.28rem 0.6rem;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 40%, transparent);
    max-width: 280px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: text;
    user-select: text;
  }

  .db-table tbody tr {
    height: 29px; /* Must match DB_ROW_HEIGHT constant in script */
  }

  .db-table tbody tr:hover td {
    background: color-mix(in srgb, var(--surface2) 60%, transparent);
  }

  .db-table tbody tr.row-selected td {
    background: color-mix(in srgb, var(--accent) 18%, transparent);
  }

  .virt-spacer td {
    padding: 0;
    border: none;
  }

  .col-check {
    width: 36px;
    text-align: center;
    cursor: default;
    user-select: none;
  }

  .db-empty {
    text-align: center;
    color: var(--muted);
    font-style: italic;
    padding: 1rem !important;
    cursor: default !important;
  }

  .db-row-count {
    font-size: 0.72rem;
    color: var(--muted);
    text-align: left;
    flex-shrink: 0;
  }

  /* ── Game tab ────────────────────────────────────────────────────────── */

  .game-dir-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .game-dir-input {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.5rem;
    font-size: 0.8rem;
    color: var(--text);
    min-width: 0;
    cursor: default;
  }

  .game-dir-error {
    font-size: 0.78rem;
    color: var(--danger);
    margin-top: 0.4rem;
    line-height: 1.4;
  }

  .game-launch-row {
    display: flex;
    gap: 0.5rem;
  }

  .patch-note {
    font-size: 0.75rem;
    color: var(--muted);
    margin-bottom: 0.5rem;
  }

  .patch-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.4rem;
  }

  .patch-bar-track {
    position: relative;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    margin-top: 0.5rem;
    overflow: hidden;
  }

  .patch-bar-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.08s linear;
  }

  @keyframes patch-slide {
    0%   { transform: translateX(-100%); }
    60%  { transform: translateX(350%); }
    100% { transform: translateX(350%); }
  }

  .patch-bar-fill--indeterminate {
    position: absolute;
    width: 30%;
    animation: patch-slide 1.2s ease-in-out infinite;
  }

  .patch-status {
    font-size: 0.78rem;
    color: var(--muted);
    margin-top: 0.5rem;
  }

  .patch-status--error {
    color: var(--danger);
  }

  /* ── Hint bar + actions ──────────────────────────────────────────────── */

  .hint-bar {
    min-height: 1.6rem;
    display: flex;
    align-items: center;
    font-size: 0.78rem;
    color: var(--muted);
    padding: 0 0.2rem;
    border-top: 1px solid var(--border);
    margin-top: auto;
    flex-shrink: 0;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
    padding-top: 0.4rem;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
  }

  .btn-primary {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 5px;
    padding: 0.4rem 1.4rem;
    font-size: 0.9rem;
    cursor: pointer;
    font-weight: 600;
  }

  .btn-primary:hover { filter: brightness(1.15); }

  .btn-secondary {
    background: var(--surface2);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 0.4rem 1rem;
    font-size: 0.9rem;
    cursor: pointer;
  }

  .btn-secondary:hover { filter: brightness(1.1); }

  /* ── Delete confirmation overlay ─────────────────────────────────────── */

  .confirm-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 200;
  }

  .confirm-box {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    display: flex;
    flex-direction: column;
    gap: 1rem;
    min-width: 280px;
  }

  .confirm-box p { font-size: 0.875rem; }

  .confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
  }

  .confirm-actions button {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.3rem 1rem;
    font-size: 0.82rem;
    color: var(--text);
    cursor: pointer;
  }

  .confirm-actions button:hover { filter: brightness(1.1); }

  .db-btn--danger-solid {
    background: var(--danger);
    color: #fff;
    border-color: var(--danger);
  }
</style>
