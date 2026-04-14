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

  let activeTab = $state("general");
  let statusMsg = $state("");
  let validating = $state(false);
  let hintText = $state("");

  // Mutual exclusion: only one translation provider active at a time
  function selectDeepL() {
    useDeepL = true; useGoogle = false; useGoogleFree = false;
  }
  function selectGoogle() {
    useDeepL = false; useGoogle = true; useGoogleFree = false;
  }
  function selectGoogleFree() {
    useDeepL = false; useGoogle = false; useGoogleFree = true;
  }
  function clearTranslation() {
    useDeepL = false; useGoogle = false; useGoogleFree = false;
  }

  function toggleDeepL() {
    if (useDeepL) clearTranslation(); else selectDeepL();
  }
  function toggleGoogle() {
    if (useGoogle) clearTranslation(); else selectGoogle();
  }
  function toggleGoogleFree() {
    if (useGoogleFree) clearTranslation(); else selectGoogleFree();
  }

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
    // Save config first
    await invoke("save_config", {
      launcher: {
        nameplates,
        update_game_files: updateGameFiles,
        disable_updates: disableUpdates,
        debug_logging: debugLogging,
        community_logging: communityLogging,
      },
      translation: {
        enabledeepltranslate:     useDeepL,
        deepltranslatekey:        deepLKey,
        enablegoogletranslate:    useGoogle,
        googletranslatekey:       googleKey,
        enablegoogletranslatefree: useGoogleFree,
        enablecommunityapi:       useCommunityApi,
        communityapikey:          communityApiKey,
      },
    });

    // Build CLI args
    const args = [];
    if (nameplates)      args.push("--nameplates");
    if (updateGameFiles) args.push("--update-dat");
    if (disableUpdates)  args.push("--disable-update-check");
    if (debugLogging)    args.push("--debug");
    if (communityLogging)args.push("--community-logging");
    if (purgeCache)      args.push("--purge-cache");
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
      <button class:active={activeTab === "general"} onclick={() => activeTab = "general"}>General</button>
      <button class:active={activeTab === "advanced"} onclick={() => activeTab = "advanced"}>Advanced</button>
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
    align-items: flex-start;
    justify-content: center;
    padding-top: 1.2rem;
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
  }

  .tabs {
    display: flex;
    gap: 2px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0.4rem;
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

  .tab-content {
    display: flex;
    flex-direction: column;
    gap: 0.7rem;
    flex: 1;
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

  .hint-bar {
    min-height: 1.6rem;
    display: flex;
    align-items: center;
    font-size: 0.78rem;
    color: var(--muted);
    padding: 0 0.2rem;
    border-top: 1px solid var(--border);
    margin-top: auto;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
    padding-top: 0.4rem;
    border-top: 1px solid var(--border);
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
