<script>
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount, onDestroy } from "svelte";

  let { ondone } = $props();

  const STEPS = [
    { id: "path_check",    label: "Checking installation path" },
    { id: "python_check",  label: "Locating Python 3.11 (32-bit)" },
    { id: "python_install",label: "Installing Python 3.11.3" },
    { id: "venv_setup",    label: "Setting up virtual environment" },
    { id: "deps_install",  label: "Installing dependencies" },
    { id: "verify",        label: "Verifying installation" },
  ];

  let stepStatus = $state(Object.fromEntries(STEPS.map(s => [s.id, "pending"])));
  let stepMessage = $state(Object.fromEntries(STEPS.map(s => [s.id, ""])));
  let pipLines = $state([]);
  let errorMessage = $state("");
  let done = $state(false);
  let showUacModal = $state(false);

  let unlisten;

  onMount(async () => {
    unlisten = await listen("setup-step", (event) => {
      const { step, status, message } = event.payload;
      if (step === "pip_output") {
        if (message.trim()) pipLines = [...pipLines, message];
        return;
      }
      if (step === "uac_prompt") {
        showUacModal = true;
        return;
      }
      stepStatus[step] = status;
      stepMessage[step] = message;
      if (step === "python_install" && (status === "done" || status === "error")) {
        showUacModal = false;
      }
    });

    try {
      await invoke("run_setup");
      done = true;
      setTimeout(() => ondone(), 600);
    } catch (e) {
      errorMessage = typeof e === "string" ? e : JSON.stringify(e);
    }
  });

  onDestroy(() => {
    if (unlisten) unlisten();
  });

  function retry() {
    errorMessage = "";
    pipLines = [];
    stepStatus = Object.fromEntries(STEPS.map(s => [s.id, "pending"]));
    stepMessage = Object.fromEntries(STEPS.map(s => [s.id, ""]));
    done = false;
    invoke("run_setup")
      .then(() => { done = true; setTimeout(() => ondone(), 600); })
      .catch(e => { errorMessage = typeof e === "string" ? e : JSON.stringify(e); });
  }

  function iconFor(status) {
    if (status === "done") return "✓";
    if (status === "error") return "✗";
    return "·";
  }
</script>

<div class="setup">
  <div class="header">
    <img src="/characters/Rosie.png" alt="Rosie" class="mascot" />
    <div class="title-block">
      <h1>dqxclarity</h1>
      <p class="subtitle">Setting up environment…</p>
    </div>
  </div>

  <div class="steps">
    {#each STEPS as step}
      {@const status = stepStatus[step.id]}
      {#if status !== "pending" || STEPS.findIndex(s => s.id === step.id) === 0}
        <div class="step" class:done={status === "done"} class:error={status === "error"} class:running={status === "running"}>
          <span class="icon">
            {#if status === "running"}
              <span class="spinner"></span>
            {:else}
              {iconFor(status)}
            {/if}
          </span>
          <span class="label">{step.label}</span>
          {#if stepMessage[step.id] && status !== "done"}
            <span class="msg">{stepMessage[step.id]}</span>
          {/if}
        </div>
      {/if}
    {/each}
  </div>

  {#if pipLines.length > 0}
    <details class="pip-output">
      <summary>pip output ({pipLines.length} lines)</summary>
      <pre>{pipLines.join("\n")}</pre>
    </details>
  {/if}

  {#if errorMessage}
    <div class="error-box">
      <p>{errorMessage}</p>
      <button onclick={retry}>Retry</button>
    </div>
  {/if}
</div>

{#if showUacModal}
  <div class="uac-overlay">
    <div class="uac-box">
      <p class="uac-title">Administrator permission required</p>
      <p class="uac-body">Windows is asking for permission to install Python. Click <strong>Yes</strong> on the prompt to continue, then click OK.</p>
      <div class="uac-actions">
        <button onclick={() => showUacModal = false}>OK</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .setup {
    display: flex;
    flex-direction: column;
    gap: 1.2rem;
    padding: 1.5rem;
    height: 100%;
    box-sizing: border-box;
  }

  .header {
    display: flex;
    align-items: center;
    gap: 1rem;
    border-bottom: 1px solid var(--border);
    padding-bottom: 1rem;
  }

  .mascot {
    width: 72px;
    height: auto;
    object-fit: contain;
  }

  h1 {
    margin: 0;
    font-size: 1.4rem;
    color: var(--accent);
  }

  .subtitle {
    margin: 0.2rem 0 0;
    font-size: 0.85rem;
    color: var(--muted);
  }

  .steps {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    flex: 1;
  }

  .step {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    font-size: 0.9rem;
    color: var(--muted);
    transition: color 0.2s;
  }

  .step.done   { color: var(--success); }
  .step.error  { color: var(--danger); }
  .step.running { color: var(--text); }

  .icon {
    font-size: 1rem;
    width: 1rem;
    text-align: center;
    flex-shrink: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .spinner {
    display: inline-block;
    width: 0.75rem;
    height: 0.75rem;
    border: 1.5px solid var(--border);
    border-top-color: var(--muted);
    border-radius: 50%;
    animation: spin 0.75s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .label { flex: 1; }

  .msg {
    font-size: 0.75rem;
    color: var(--muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 280px;
  }

  .pip-output {
    font-size: 0.75rem;
    color: var(--muted);
  }

  .pip-output pre {
    background: var(--surface2);
    padding: 0.5rem;
    border-radius: 4px;
    max-height: 100px;
    overflow-y: auto;
    margin: 0.25rem 0 0;
    font-size: 0.7rem;
  }

  .error-box {
    background: color-mix(in srgb, var(--danger) 15%, var(--surface));
    border: 1px solid var(--danger);
    border-radius: 6px;
    padding: 0.8rem 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }

  .error-box p {
    margin: 0;
    flex: 1;
    font-size: 0.85rem;
    color: var(--danger);
  }

  .error-box button {
    background: var(--danger);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 0.3rem 0.8rem;
    cursor: pointer;
    font-size: 0.85rem;
  }

  .uac-overlay {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .uac-box {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1.2rem 1.4rem;
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    max-width: 340px;
  }

  .uac-title {
    font-size: 0.9rem;
    font-weight: 600;
    color: var(--text);
    margin: 0;
  }

  .uac-body {
    font-size: 0.82rem;
    color: var(--muted);
    margin: 0;
    line-height: 1.5;
  }

  .uac-actions {
    display: flex;
    justify-content: flex-end;
  }

  .uac-actions button {
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 4px;
    padding: 0.3rem 1rem;
    font-size: 0.82rem;
    cursor: pointer;
    font-weight: 600;
  }

  .uac-actions button:hover { filter: brightness(1.1); }
</style>
