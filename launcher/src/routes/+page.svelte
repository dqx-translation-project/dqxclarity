<script>
  import { invoke } from "@tauri-apps/api/core";
  import { applyTheme } from "$lib/themes.js";
  import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { LogicalSize } from "@tauri-apps/api/window";
  import { onMount } from "svelte";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import Setup from "$lib/Setup.svelte";
  import Settings from "$lib/Settings.svelte";
  import Log from "$lib/Log.svelte";

  let view = $state("setup");  // "setup" | "settings" | "log"
  let config = $state(null);
  let version = $state("???");
  let showSupport = $state(false);
  let copied = $state(false);

  const DISCORD = "https://discord.gg/dragonquestx";

  const WIN_SIZES = {
    setup:    { w: 500, h: 360 },
    settings: { w: 680, h: 480 },
    log:      { w: 680, h: 550 },
  };

  async function setWindowSize(v) {
    try {
      const win = getCurrentWebviewWindow();
      const { w, h } = WIN_SIZES[v];
      await win.setSize(new LogicalSize(w, h));
    } catch (_) {}
  }

  async function switchTo(v) {
    await setWindowSize(v);
    view = v;
  }

  onMount(async () => {
    // Run INI migration if needed, then load config
    await invoke("migrate_ini").catch(() => {});
    config = await invoke("load_config").catch(() => ({ launcher: {}, translation: {} }));
    version = await invoke("get_version").catch(() => "???");
    applyTheme(config?.launcher?.theme ?? "rosie");
    await setWindowSize("setup");
  });

  async function onSetupDone() {
    await switchTo("settings");
  }

  async function onRun(args) {
    await switchTo("log");
    await invoke("launch_clarity", { args }).catch((e) => {
      console.error("launch failed", e);
    });
  }

  function openSupport() {
    copied = false;
    showSupport = true;
  }

  async function copyDiscord() {
    await navigator.clipboard.writeText(DISCORD);
    copied = true;
    setTimeout(() => { copied = false; }, 2000);
  }
</script>

{#if view === "setup"}
  <Setup ondone={onSetupDone} />
{:else if view === "settings" && config}
  <Settings {config} onrun={onRun} />
{:else if view === "log"}
  <Log onstop={() => switchTo("settings")} />
{/if}

{#if showSupport}
  <!-- svelte-ignore a11y_click_events_have_key_events -->
  <div class="overlay" role="presentation" onclick={() => showSupport = false}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <div class="popup" role="dialog" aria-modal="true" onclick={(e) => e.stopPropagation()}>
      <p class="popup-title">Support</p>
      <div class="field-row">
        <label for="discord-link">Discord:</label>
        <input id="discord-link" type="text" value={DISCORD} readonly />
        <button class="copy-btn" class:copied onclick={copyDiscord}>
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>
    </div>
  </div>
{/if}

<div class="bottom-left">
  <button class="support-link" onclick={() => openUrl("https://dqx-translation-project.github.io/")}>Wiki</button>
  <button class="support-link" onclick={openSupport}>Support</button>
  <span class="version">v{version}</span>
</div>

<style>
  :global(:root) {
    --bg:       #1a1a1f;
    --surface:  #1e1e24;
    --surface2: #26262e;
    --border:   #35353f;
    --text:     #e2e2e8;
    --muted:    #7a7a8c;
    --accent:   #01524E;
    --success:  #4caf82;
    --danger:   #e05c6a;
  }

  :global(*) {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  :global(body) {
    background: var(--bg);
    color: var(--text);
    font-family: "Segoe UI", system-ui, sans-serif;
    font-size: 14px;
    height: 100vh;
    overflow: hidden;
  }

  :global(#svelte) {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  .bottom-left {
    position: fixed;
    bottom: 0.35rem;
    left: 0.5rem;
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.1rem;
    pointer-events: none;
  }

  .support-link {
    pointer-events: all;
    background: none;
    border: none;
    padding: 0;
    font-size: 0.8rem;
    color: var(--muted);
    cursor: pointer;
    text-decoration: underline;
  }

  .support-link:hover {
    color: var(--text);
  }

  .version {
    font-size: 0.8rem;
    color: var(--muted);
    user-select: none;
  }

  .overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .popup {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
    min-width: 360px;
  }

  .popup-title {
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--text);
  }

  .field-row {
    display: flex;
    align-items: center;
    gap: 0.6rem;
  }

  .field-row label {
    font-size: 0.82rem;
    color: var(--muted);
    white-space: nowrap;
  }

  .field-row input {
    flex: 1;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.5rem;
    font-size: 0.8rem;
    color: var(--text);
    cursor: default;
    min-width: 0;
  }

  .copy-btn {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0.25rem 0.65rem;
    font-size: 0.8rem;
    color: var(--text);
    cursor: pointer;
    white-space: nowrap;
    transition: color 0.15s, border-color 0.15s;
  }

  .copy-btn.copied {
    color: var(--success);
    border-color: var(--success);
  }
</style>
