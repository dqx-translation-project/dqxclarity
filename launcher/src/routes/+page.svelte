<script>
  import { invoke } from "@tauri-apps/api/core";
  import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
  import { LogicalSize } from "@tauri-apps/api/window";
  import { onMount } from "svelte";
  import Setup from "$lib/Setup.svelte";
  import Settings from "$lib/Settings.svelte";
  import Log from "$lib/Log.svelte";

  let view = $state("setup");  // "setup" | "settings" | "log"
  let config = $state(null);

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
</script>

{#if view === "setup"}
  <Setup ondone={onSetupDone} />
{:else if view === "settings" && config}
  <Settings {config} onrun={onRun} />
{:else if view === "log"}
  <Log onstop={() => switchTo("settings")} />
{/if}

<style>
  :global(:root) {
    --bg:       #1a1a1f;
    --surface:  #1e1e24;
    --surface2: #26262e;
    --border:   #35353f;
    --text:     #e2e2e8;
    --muted:    #7a7a8c;
    --accent:   #03F4F2;
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
</style>
