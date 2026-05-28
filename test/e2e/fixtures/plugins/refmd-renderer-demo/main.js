const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD renderer demo plugin");
root.innerHTML = `
  <h1>RefMD Renderer Demo Plugin</h1>
  <section>
    <h2>Renderer Invocation</h2>
    <p data-role="status">Waiting</p>
    <dl>
      <dt>Kind</dt>
      <dd data-role="kind">none</dd>
      <dt>Type</dt>
      <dd data-role="type">none</dd>
      <dt>Source</dt>
      <dd data-role="source">none</dd>
    </dl>
  </section>
`;
document.body.append(root);

function attachRuntimeListener() {
  const renderer = globalThis.refmd?.renderer;
  if (!renderer) {
    window.setTimeout(attachRuntimeListener, 25);
    return;
  }

  renderer.register_block("refmd-renderer-demo", (context) => render(context));
  renderer.register_inline_code((context) => render(context));
}

async function render(context) {
  const status = root.querySelector('[data-role="status"]');
  try {
    const source = await context.getSource();
    setText("status", "Mounted");
    setText("kind", context.kind ?? "unknown");
    setText("type", context.type ?? "unknown");
    setText("source", source ?? "");
    return {
      rendered: true,
      kind: context.kind,
      type: context.type,
    };
  } catch (error) {
    if (status) status.textContent = `Failed: ${error?.message ?? String(error)}`;
    return {
      rendered: false,
      error: error?.message ?? String(error),
    };
  }
}

function setText(role, value) {
  const target = root.querySelector(`[data-role="${role}"]`);
  if (target) target.textContent = String(value);
}

attachRuntimeListener();

export default {};
