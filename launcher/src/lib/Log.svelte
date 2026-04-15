<script>
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy, tick } from "svelte";

  let { onstop } = $props();

  let lines = $state([]);
  let logEl;
  let unlisten1, unlisten2;

  onMount(async () => {
    const MAX_LINES = 1000;
    unlisten1 = await listen("log-line", (event) => {
      const next = [...lines, event.payload];
      lines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next;
      tick().then(() => {
        if (logEl) logEl.scrollTop = logEl.scrollHeight;
      });
    });

    unlisten2 = await listen("process-exited", () => {
      onstop();
    });
  });

  onDestroy(() => {
    if (unlisten1) unlisten1();
    if (unlisten2) unlisten2();
  });

  async function stop() {
    await invoke("stop_clarity");
  }

  // ANSI color codes → CSS colors (tuned for dark background)
  const FG = {
    30: "#555e70", 31: "#f38ba8", 32: "#a6e3a1", 33: "#f9e2af",
    34: "#89b4fa", 35: "#cba6f7", 36: "#89dceb", 37: "#cdd6f4",
    90: "#7f849c", 91: "#f38ba8", 92: "#a6e3a1", 93: "#f9e2af",
    94: "#89b4fa", 95: "#cba6f7", 96: "#94e2d5", 97: "#ffffff",
  };

  function ansiToHtml(text) {
    let html = "";
    let color = null;
    let bold = false;

    // Split on ESC[ ... m sequences; odd indices are the captured code groups
    const parts = text.split(/\x1b\[([0-9;]*)m/);

    for (let i = 0; i < parts.length; i++) {
      if (i % 2 === 0) {
        // Text segment — escape HTML then wrap in span if styled
        const escaped = parts[i]
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;");
        if (!escaped) continue;
        const styles = [];
        if (color) styles.push(`color:${color}`);
        if (bold)  styles.push("font-weight:bold");
        html += styles.length
          ? `<span style="${styles.join(";")}">${escaped}</span>`
          : escaped;
      } else {
        // Code segment — update current style state
        for (const code of parts[i].split(";").map(Number)) {
          if (code === 0)          { color = null; bold = false; }
          else if (code === 1)     { bold = true; }
          else if (FG[code])       { color = FG[code]; }
        }
      }
    }

    return html;
  }
</script>

<div class="log-view">
  <div class="toolbar">
    <span class="title">dqxclarity — running</span>
    <div class="actions">
      <button class="btn-danger" onclick={stop}>Stop</button>
    </div>
  </div>

  <div class="log" bind:this={logEl}>
    {#each lines as entry}
      <div class="line" class:err={entry.level === "error"}>{@html ansiToHtml(entry.line)}</div>
    {/each}
    {#if lines.length === 0}
      <div class="line muted">Waiting for output…</div>
    {/if}
  </div>

</div>

<style>
  .log-view {
    display: flex;
    flex-direction: column;
    height: 100%;
  }

  .toolbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0.8rem;
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .title {
    font-size: 0.85rem;
    color: var(--muted);
  }

  .actions {
    display: flex;
    gap: 0.5rem;
  }

  .log {
    flex: 1;
    overflow-y: auto;
    padding: 0.6rem 0.8rem;
    font-family: "Cascadia Code", "Consolas", "Courier New", monospace;
    font-size: 0.78rem;
    line-height: 1.5;
    background: var(--surface);
  }

  .line { color: var(--text); white-space: pre-wrap; word-break: break-all; }
  .line.err   { color: var(--danger); }
  .line.muted { color: var(--muted); font-style: italic; }

  .btn-danger {
    background: var(--danger);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 0.25rem 0.7rem;
    font-size: 0.8rem;
    cursor: pointer;
  }


</style>
