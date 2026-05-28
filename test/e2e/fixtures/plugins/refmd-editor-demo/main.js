const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD editor demo plugin");
root.innerHTML = `
  <h1>RefMD Editor Demo Plugin</h1>
  <p data-role="status">Registering editor contributions</p>
`;
document.body.append(root);

function setStatus(value) {
  const target = root.querySelector('[data-role="status"]');
  if (target) target.textContent = value;
}

function hostRpc() {
  const runtime = globalThis.refmd;
  if (!runtime || runtime.runtime?.connected !== true) return null;
  if (!runtime.runtime.context || typeof runtime.runtime.context.frame_scope !== "string") return null;
  return runtime;
}

function errorResponse(message, error) {
  message.respond({
    error: {
      code: "editor_demo_failed",
      message: error?.message ?? String(error),
    },
  });
}

async function getPlaintext(operation, message) {
  const runtime = hostRpc();
  const options = {
    executionContextId: message.executionContextId,
    resource: message.resource,
  };
  if (operation === "formatter.getInput") return runtime.editor.getFormatterInput({}, options);
  if (operation === "diagnostics.getContext") return runtime.editor.getDiagnosticsContext({}, options);
  if (operation === "decoration.getContext") return runtime.editor.getDecorationContext({}, options);
  if (operation === "suggestion.getContext") return runtime.editor.getSuggestionContext({}, options);
  throw new Error("editor_context_operation_invalid");
}

function targetRange(context) {
  const plaintext = String(context?.plaintext ?? "");
  const base = Math.min(Number(context?.range?.anchor ?? 0), Number(context?.range?.head ?? 0));
  const needle = "editor-demo-target";
  const index = plaintext.indexOf(needle);
  if (index < 0) return { from: base, to: Math.min(base + 1, base + plaintext.length) };
  return { from: base + index, to: base + index + needle.length };
}

async function handleRequest(message) {
  try {
    if (message.operation === "editor.command.run") {
      setStatus("Command invoked");
      message.respond({ handled: true });
      return;
    }

    if (message.operation === "formatter.run") {
      setStatus("Formatter invoked");
      const input = await getPlaintext("formatter.getInput", message);
      const from = Math.min(Number(input.range.anchor), Number(input.range.head));
      const to = Math.max(Number(input.range.anchor), Number(input.range.head));
      setStatus(`Formatter completed: ${from}-${to}`);
      message.respond({
        edits: [
          {
            range: { from, to },
            text: "# Editor Demo Formatted\n\nEDITOR DEMO FORMATTED\n\neditor-demo-target\n",
          },
        ],
      });
      return;
    }

    if (message.operation === "diagnostics.run") {
      const context = await getPlaintext("diagnostics.getContext", message);
      message.respond({
        diagnostics: [
          {
            range: targetRange(context),
            severity: "warning",
            message: "Editor demo diagnostic",
            source: "RefMD Editor Demo",
          },
        ],
      });
      return;
    }

    if (message.operation === "decoration.run") {
      const context = await getPlaintext("decoration.getContext", message);
      message.respond({
        decorations: [
          {
            id: "editor-demo-highlight",
            range: targetRange(context),
            style: "highlight",
            tone: "warning",
          },
        ],
      });
      return;
    }

    if (message.operation === "suggestion.run") {
      const context = await getPlaintext("suggestion.getContext", message);
      message.respond({
        suggestions: [
          {
            id: "editor-demo-suggestion",
            label: "Apply editor demo suggestion",
            insert_text: "editor-demo-suggested",
            range: targetRange(context),
            detail: "Replace the editor demo target",
          },
        ],
      });
      return;
    }
  } catch (error) {
    setStatus(`Failed: ${error?.message ?? String(error)}`);
    errorResponse(message, error);
  }
}

async function registerEditorContributions() {
  const runtime = hostRpc();
  if (!runtime) {
    window.setTimeout(registerEditorContributions, 25);
    return;
  }

  if (runtime.runtime.context?.frame_scope !== "primary") {
    setStatus("Editor Demo Panel");
    return;
  }

  runtime.editor.onRequest((message) => {
    void handleRequest(message);
  });

  try {
    await runtime.editor.registerContribution( {
      kind: "editor_command",
      id: "editor.demo.command",
      title: "Editor Demo Command",
    });
    await runtime.editor.registerContribution( {
      kind: "formatter",
      id: "editor.demo.formatter",
      title: "Editor Demo Formatter",
      input: "selection",
    });
    await runtime.editor.registerContribution( {
      kind: "diagnostics",
      id: "editor.demo.diagnostics",
      title: "Editor Demo Diagnostics",
      input: "editor_context",
    });
    await runtime.editor.registerContribution( {
      kind: "decoration",
      id: "editor.demo.decoration",
      title: "Editor Demo Decoration",
      input: "editor_context",
      trigger: "visible_context",
      max_decorations: 8,
    });
    await runtime.editor.registerContribution( {
      kind: "suggestion",
      id: "editor.demo.suggestion",
      title: "Editor Demo Suggestion",
      input: "editor_context",
    });
    setStatus("Editor contributions registered");
  } catch (error) {
    setStatus(`Registration failed: ${error?.message ?? String(error)}`);
  }
}

registerEditorContributions();

export default {};
