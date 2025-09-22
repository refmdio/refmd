use anyhow::Context;

pub struct ExtismExecOptions<'a> {
    pub plugin_dir: &'a std::path::Path,
    pub func: &'a str,
    pub input: Vec<u8>,
}

pub fn call_extism(opts: ExtismExecOptions) -> anyhow::Result<Vec<u8>> {
    // Determine wasm path from plugin.json or default to backend/plugin.wasm
    let manifest_path = opts.plugin_dir.join("plugin.json");
    let wasm_rel = if let Ok(s) = std::fs::read_to_string(&manifest_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            v.get("backend")
                .and_then(|b| b.get("wasm"))
                .and_then(|w| w.as_str())
                .map(|s| s.to_string())
        } else {
            None
        }
    } else {
        None
    };
    let wasm_path = opts
        .plugin_dir
        .join(wasm_rel.unwrap_or_else(|| "backend/plugin.wasm".to_string()));

    let wasm = extism::Wasm::file(&wasm_path);
    let manifest = extism::Manifest::new([wasm]);
    let mut plugin = extism::Plugin::new(&manifest, [], true).context("create plugin")?;
    let out: &[u8] = plugin
        .call(opts.func, &opts.input)
        .map_err(|e| anyhow::anyhow!(format!("extism call error: {}", e)))?;
    Ok(out.to_vec())
}
