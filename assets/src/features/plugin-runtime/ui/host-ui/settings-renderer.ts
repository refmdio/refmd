import { PluginHostRpcError } from "../../lib/host-rpc/host-rpc";
import type {
  PluginUiFormField,
  PluginUiIframeSurface,
  PluginUiSettingsRendererOptions,
  PluginUiSettingsSubmitPayload,
  PluginUiSettingsDeclarativeContribution,
  PluginUiSettingsIframeContribution,
} from "../../model/host-ui/host-ui";

export function renderPluginUiSettingsContribution(
  container: HTMLElement,
  contribution: PluginUiSettingsIframeContribution | PluginUiSettingsDeclarativeContribution,
  id: string,
  iframeSurface: PluginUiIframeSurface | undefined,
  options: PluginUiSettingsRendererOptions = {},
): void {
  container.replaceChildren();
  if (contribution.surface === "settings_iframe") {
    if (!iframeSurface) {
      throw new PluginHostRpcError(
        "ui_iframe_surface_unavailable",
        "sandboxed UI iframe surface is unavailable",
      );
    }
    iframeSurface.mount({
      id,
      surface: "settings_iframe",
      title: contribution.title,
      container,
    });
    return;
  }

  const form = document.createElement("form");
  form.className = "space-y-3";

  for (const section of contribution.sections) {
    const sectionEl = document.createElement("section");
    sectionEl.className = "space-y-3 py-2";
    if (section.title) {
      const heading = document.createElement("h3");
      heading.className = "text-sm font-medium";
      heading.textContent = section.title;
      sectionEl.appendChild(heading);
    }
    for (const field of section.fields) {
      sectionEl.appendChild(renderSettingsField(field));
    }
    form.appendChild(sectionEl);
  }

  if (contribution.submit_command_ref) {
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.className = "h-9 rounded-md border border-input px-3 text-sm font-medium";
    submit.textContent = "Submit";
    form.appendChild(submit);
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!contribution.submit_command_ref || !options.submit) return;
    options.submit(settingsSubmitPayload(contribution, form));
  });

  container.appendChild(form);
}

function renderSettingsField(field: PluginUiFormField): HTMLElement {
  const wrapper = document.createElement("label");
  wrapper.className = "grid gap-1.5 text-sm";
  const label = document.createElement("span");
  label.className = "font-medium";
  label.textContent = field.label;
  wrapper.appendChild(label);

  if (field.kind === "checkbox") {
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = field.name;
    wrapper.appendChild(input);
    return wrapper;
  }

  if (field.kind === "select") {
    const select = document.createElement("select");
    select.name = field.name;
    select.className = "h-9 rounded-md border border-input bg-background px-3 text-sm";
    for (const option of field.options) {
      const optionEl = document.createElement("option");
      optionEl.value = option.value;
      optionEl.textContent = option.label;
      select.appendChild(optionEl);
    }
    wrapper.appendChild(select);
    return wrapper;
  }

  const input =
    field.kind === "textarea"
      ? document.createElement("textarea")
      : document.createElement("input");
  input.name = field.name;
  input.maxLength = field.max_length;
  input.className = "min-h-9 rounded-md border border-input bg-background px-3 py-2 text-sm";
  wrapper.appendChild(input);
  return wrapper;
}

function settingsSubmitPayload(
  contribution: PluginUiSettingsDeclarativeContribution,
  form: HTMLFormElement,
): PluginUiSettingsSubmitPayload {
  const data = new FormData(form);
  const values: PluginUiSettingsSubmitPayload["values"] = {};

  for (const section of contribution.sections) {
    for (const field of section.fields) {
      if (field.kind === "checkbox") {
        values[field.name] = data.has(field.name);
      } else {
        const value = data.get(field.name);
        values[field.name] = typeof value === "string" ? value : "";
      }
    }
  }

  return { settings_id: contribution.settings_id, values };
}
