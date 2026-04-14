<script>
  import { invoke } from "@tauri-apps/api/core";
  import { openUrl } from "@tauri-apps/plugin-opener";

  let { config, onrun } = $props();

  // --- Launcher settings (Tauri owns these) ---
  let nameplates       = $state(config?.launcher?.nameplates       ?? false);
  let updateGameFiles  = $state(config?.launcher?.update_game_files ?? false);
  let disableUpdates   = $state(config?.launcher?.disable_updates   ?? false);
  let debugLogging     = $state(config?.launcher?.debug_logging     ?? false);
  let communityLogging = $state(config?.launcher?.community_logging ?? false);
  let purgeCache       = $state(false); // session-only, never persisted

  // --- Translation settings (Python owns these, we just display/edit) ---
  let useDeepL          = $state(config?.translation?.enabledeepltranslate    ?? false);
  let deepLKey          = $state(config?.translation?.deepltranslatekey        ?? "");
  let useGoogle         = $state(config?.translation?.enablegoogletranslate    ?? false);
  let googleKey         = $state(config?.translation?.googletranslatekey       ?? "");
  let useGoogleFree     = $state(config?.translation?.enablegoogletranslatefree ?? false);
  let useCommunityApi   = $state(config?.translation?.enablecommunityapi       ?? false);
  let communityApiKey   = $state(config?.translation?.communityapikey          ?? "");

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

  // ── Helpers for error highlighting ───────────────────────────────────────

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
      errors.push({ message: 'Root value must be an object', ranges: [] });
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

  // ── Name overrides actions ────────────────────────────────────────────────

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

  // ── General/Advanced tab logic ────────────────────────────────────────────

  function selectDeepL()      { useDeepL = true;  useGoogle = false; useGoogleFree = false; }
  function selectGoogle()     { useDeepL = false; useGoogle = true;  useGoogleFree = false; }
  function selectGoogleFree() { useDeepL = false; useGoogle = false; useGoogleFree = true;  }
  function clearTranslation() { useDeepL = false; useGoogle = false; useGoogleFree = false; }

  function toggleDeepL()       { if (useDeepL)      clearTranslation(); else selectDeepL();      }
  function toggleGoogle()      { if (useGoogle)     clearTranslation(); else selectGoogle();     }
  function toggleGoogleFree()  { if (useGoogleFree) clearTranslation(); else selectGoogleFree(); }

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

    onrun(args);
  }

  function openGitHub() {
    openUrl("https://github.com/dqx-translation-project/dqxclarity");
  }
</script>

<div class="settings">
  <div class="sidebar">
    <img src="/rosie.png" alt="Rosie" class="mascot" />
  </div>

  <div class="content">
    <!-- Tabs -->
    <div class="tabs">
      <button class:active={activeTab === "general"}       onclick={() => activeTab = "general"}>General</button>
      <button class:active={activeTab === "advanced"}      onclick={() => activeTab = "advanced"}>Advanced</button>
      <button class:active={activeTab === "nameoverrides"} onclick={openNameOverridesTab}>Name Overrides</button>
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
          <!-- Left: editable -->
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

          <!-- Right: read-only example -->
          <div class="example-pane">
            <div class="example-label">Example</div>
            <pre class="example-content">{OVERRIDES_EXAMPLE}</pre>
          </div>
        </div>

        <div class="overrides-actions">
          <span class="overrides-desc">Override Japanese player and MyTown names with your own, custom names.</span>
          <button
            class="btn-save"
            onclick={saveNameOverrides}
            onmouseenter={() => hintText = "Save changes to name_overrides.json."}
            onmouseleave={() => hintText = ""}
          >Save</button>
        </div>
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

<style>
  .settings {
    display: flex;
    height: 100%;
  }

  .sidebar {
    width: 130px;
    background: var(--surface2);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .mascot {
    width: 110px;
    height: auto;
    object-fit: contain;
  }

  .content {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 1rem 1.2rem;
    gap: 0.6rem;
    overflow-y: auto;
    min-height: 0;
  }

  /* ── Tabs ───────────────────────────────────────────────────────────────── */

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

  /* ── General / Advanced tab content ─────────────────────────────────────── */

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

  .api-toggle {
    min-width: 160px;
    flex-shrink: 0;
  }

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

  .api-key:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

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

  .validate-row button:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  .status-msg {
    font-size: 0.78rem;
    color: var(--muted);
  }

  /* ── Name Overrides tab ──────────────────────────────────────────────────── */

  .overrides-content {
    gap: 0.5rem;
  }

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

  /* Editor: wrapper holds background + border; textarea is transparent so
     the backdrop's error underlines show through. */
  .editor-wrapper {
    position: relative;
    flex: 1;
    min-height: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  .editor-wrapper:focus-within {
    border-color: var(--muted);
  }

  /* Backdrop clips to the wrapper bounds; its inner div shifts via transform
     in sync with the textarea's scroll position. */
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
    color: transparent; /* Text is invisible; only err-mark decorations show */
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

  .overrides-desc {
    font-size: 0.75rem;
    color: var(--muted);
  }

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

  /* ── Hint bar + actions ──────────────────────────────────────────────────── */

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
</style>
