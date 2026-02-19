//! Build script for component-macro.
//!
//! Locates `Components.toml` in the kernel workspace, registers it for
//! incremental-rebuild tracking, and validates the dependency graph at
//! compile time (detects unknown deps and cycles).

fn main() {
    // Walk up from this crate's manifest dir to find Components.toml.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut search = std::path::PathBuf::from(&manifest_dir);

    let mut found: Option<std::path::PathBuf> = None;
    for _ in 0..6 {
        let candidate = search.join("Components.toml");
        if candidate.exists() {
            found = Some(candidate);
            break;
        }
        if !search.pop() {
            break;
        }
    }

    let Some(path) = found else {
        println!("cargo:warning=component-macro: Components.toml not found (searched from {manifest_dir})");
        return;
    };

    // Tell cargo to re-run this build script whenever Components.toml changes.
    println!("cargo:rerun-if-changed={}", path.display());

    validate_components_toml(&path);
}

// =================================================================
// Validation
// =================================================================

fn validate_components_toml(path: &std::path::Path) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("cargo:warning=component-macro: Cannot read Components.toml: {e}");
            return;
        }
    };

    // Collect component_name -> deps.
    let mut graph: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }
        let Some(eq_pos) = line.find('=') else {
            continue;
        };
        let name = line[..eq_pos].trim().to_string();
        let rest = line[eq_pos + 1..].trim();

        let deps: Vec<String> = if let Some(di) = rest.find("deps") {
            let after = rest[di + 4..]
                .trim_start_matches(|c: char| c == ' ' || c == '=')
                .trim_start();
            if let Some(bs) = after.find('[') {
                if let Some(be) = after.find(']') {
                    after[bs + 1..be]
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        graph.insert(name, deps);
    }

    // Validate: every listed dependency must be a known component.
    let mut warnings = 0usize;
    for (name, deps) in &graph {
        for dep in deps {
            if !graph.contains_key(dep.as_str()) {
                println!(
                    "cargo:warning=Components.toml: '{name}' depends on '{dep}' \
                     which is not defined"
                );
                warnings += 1;
            }
        }
    }

    // Validate: no cycles (DFS).
    if has_cycle(&graph) {
        println!("cargo:warning=Components.toml: dependency cycle detected!");
        warnings += 1;
    }

    if warnings == 0 {
        println!(
            "cargo:warning=Components.toml: OK — {} component(s) validated",
            graph.len()
        );
    }
}

fn has_cycle(graph: &std::collections::HashMap<String, Vec<String>>) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut on_stack = std::collections::HashSet::new();

    for node in graph.keys() {
        if dfs(node, graph, &mut visited, &mut on_stack) {
            return true;
        }
    }
    false
}

fn dfs(
    node: &str,
    graph: &std::collections::HashMap<String, Vec<String>>,
    visited: &mut std::collections::HashSet<String>,
    on_stack: &mut std::collections::HashSet<String>,
) -> bool {
    if on_stack.contains(node) {
        return true; // back edge → cycle
    }
    if visited.contains(node) {
        return false; // already fully explored
    }

    visited.insert(node.to_string());
    on_stack.insert(node.to_string());

    if let Some(deps) = graph.get(node) {
        for dep in deps {
            if dfs(dep, graph, visited, on_stack) {
                return true;
            }
        }
    }

    on_stack.remove(node);
    false
}
