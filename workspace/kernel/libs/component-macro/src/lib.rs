//! Procedural macros for the component initialization system.
//!
//! Provides `#[init_component]` for registering kernel component init functions
//! and `parse_components_toml!` for compile-time access to `Components.toml`.

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, ItemFn, LitInt, Token,
};

// =================================================================================
// Argument parser
// =================================================================================

/// Parsed arguments for `#[init_component(stage, priority = N, depends_on = fn_or_list)]`.
struct InitComponentArgs {
    /// "Bootstrap" | "Kthread" | "Process"  (PascalCase ready for quote!)
    stage: String,
    /// Init priority: lower = earlier within the same topological level.
    priority: u32,
    /// Names of functions (same stage) that must run before this one.
    depends_on: Vec<String>,
}

impl Parse for InitComponentArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut stage = "Bootstrap".to_string();
        let mut priority = 0u32;
        let mut depends_on = Vec::new();

        if input.is_empty() {
            return Ok(Self {
                stage,
                priority,
                depends_on,
            });
        }

        // First token: optional stage ident NOT followed by `=`.
        // e.g. `bootstrap` in `(bootstrap, priority = 1)`.
        if input.peek(Ident) && !input.peek2(Token![=]) {
            let ident: Ident = input.parse()?;
            stage = match ident.to_string().as_str() {
                "bootstrap" => "Bootstrap",
                "kthread" => "Kthread",
                "process" => "Process",
                other => {
                    return Err(syn::Error::new(
                        ident.span(),
                        format!(
                            "unknown stage '{other}'. \
                             Expected: bootstrap, kthread, or process"
                        ),
                    ));
                }
            }
            .to_string();

            // Consume comma before key=value pairs (if any).
            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            } else {
                return Ok(Self {
                    stage,
                    priority,
                    depends_on,
                });
            }
        }

        // Parse remaining `key = value` pairs.
        loop {
            if input.is_empty() {
                break;
            }

            let key: Ident = input.parse()?;
            let _: Token![=] = input.parse()?;

            match key.to_string().as_str() {
                "priority" => {
                    let lit: LitInt = input.parse()?;
                    priority = lit.base10_parse()?;
                }
                "depends_on" => {
                    depends_on = parse_depends_on(input)?;
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown argument '{other}'. \
                             Expected: priority, depends_on"
                        ),
                    ));
                }
            }

            if input.peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            } else {
                break;
            }
        }

        Ok(Self {
            stage,
            priority,
            depends_on,
        })
    }
}

/// Parse `fn_name` or `[fn1, fn2, ...]` after `depends_on =`.
fn parse_depends_on(input: ParseStream) -> syn::Result<Vec<String>> {
    if input.peek(syn::token::Bracket) {
        let content;
        syn::bracketed!(content in input);
        let names: Punctuated<Ident, Token![,]> = Punctuated::parse_terminated(&content)?;
        Ok(names.into_iter().map(|i| i.to_string()).collect())
    } else {
        let name: Ident = input.parse()?;
        Ok(vec![name.to_string()])
    }
}

/// Register a function as a kernel component initializer.
///
/// # Syntax
///
/// ```text
/// #[init_component]
/// #[init_component(bootstrap)]
/// #[init_component(bootstrap, priority = 1)]
/// #[init_component(kthread, priority = 2, depends_on = vfs_init)]
/// #[init_component(kthread, priority = 3, depends_on = [vfs_init, ipc_init])]
/// ```
///
/// | Argument     | Type             | Default     | Description                                   |
/// |--------------|------------------|-------------|-----------------------------------------------|
/// | stage        | positional ident | `bootstrap` | `bootstrap`, `kthread`, or `process`          |
/// | `priority`   | integer          | `0`         | Lower = earlier (tiebreaker within topo level)|
/// | `depends_on` | ident or list    | `[]`        | Functions that must complete before this one  |
///
/// # Example
///
/// ```rust,no_run
/// #[init_component(bootstrap, priority = 1)]
/// fn vfs_init() -> Result<(), component::ComponentInitError> {
///     vfs::init();
///     Ok(())
/// }
///
/// #[init_component(kthread, priority = 2, depends_on = vfs_init)]
/// fn fs_ext4_init() -> Result<(), component::ComponentInitError> {
///     fs_ext4::init();
///     Ok(())
/// }
/// ```
///
/// The annotated function is emitted unchanged; a companion `#[used]` static is
/// placed in `.component_entries` so `component::init_all()` can discover,
/// topologically sort, and call all registered components at runtime.
#[proc_macro_attribute]
pub fn init_component(args: TokenStream, input: TokenStream) -> TokenStream {
    let component_args = parse_macro_input!(args as InitComponentArgs);
    let function = parse_macro_input!(input as ItemFn);

    let function_name = &function.sig.ident;
    let function_name_str = function_name.to_string();
    let function_vis = &function.vis;
    let function_sig = &function.sig;
    let function_block = &function.block;

    let stage = Ident::new(&component_args.stage, Span::call_site());
    let priority = component_args.priority;
    let depends_on = &component_args.depends_on; // Vec<String> — quoted as &[str_lit, ...]

    // Static name: guaranteed unique within a crate via function name.
    let static_name = quote::format_ident!("__COMPONENT_ENTRY_{}", function_name);

    let expanded = quote! {
        #function_vis #function_sig #function_block

        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        #[link_section = ".component_entries"]
        #[used]
        static #static_name: component::ComponentEntry = component::ComponentEntry {
            name:       #function_name_str,
            stage:      component::InitStage::#stage,
            init_fn:    #function_name,
            path:       ::core::concat!(file!(), ":", ::core::stringify!(#function_name)),
            priority:   #priority,
            depends_on: &[#(#depends_on),*],
        };
    };

    TokenStream::from(expanded)
}

// ─── parse_components_toml! ──────────────────────────────────────────────────

/// Emit compile-time dependency metadata parsed from `Components.toml`.
///
/// Searches for `Components.toml` starting from the **calling crate's** manifest
/// directory and walking up to 6 levels. Returns:
///
/// ```text
/// &'static [(&'static str, &'static [&'static str])]
/// ```
///
/// Each element is `(component_name, &[dep1, dep2, ...])`.
///
/// # Example
///
/// ```rust,no_run
/// let meta = component::parse_components_toml!();
/// for (name, deps) in meta {
///     log::debug!("{} depends on {:?}", name, deps);
/// }
/// ```
#[proc_macro]
pub fn parse_components_toml(_input: TokenStream) -> TokenStream {
    // Locate Components.toml by searching up from the calling crate's dir.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());

    let mut search = std::path::PathBuf::from(&manifest_dir);
    let mut found_path: Option<std::path::PathBuf> = None;
    for _ in 0..6 {
        let candidate = search.join("Components.toml");
        if candidate.exists() {
            found_path = Some(candidate);
            break;
        }
        if !search.pop() {
            break;
        }
    }

    let entries = match found_path {
        Some(ref p) => {
            let content = std::fs::read_to_string(p)
                .unwrap_or_else(|e| panic!("Failed to read Components.toml: {e}"));
            parse_toml_deps(&content)
        }
        None => vec![],
    };

    let items = entries.iter().map(|(name, deps)| {
        quote! { (#name, &[#(#deps),*] as &[&'static str]) }
    });

    TokenStream::from(quote! {
        &[#(#items),*] as &[(&'static str, &'static [&'static str])]
    })
}

// ─── Internal TOML parser ────────────────────────────────────────────────────

/// Minimal parser for the Components.toml format used by Strat9-OS.
///
/// Handles lines of the form (one component per line):
/// ```toml
/// name = { path = "...", deps = ["dep1", "dep2"] }
/// name = { path = "...", deps = [] }
/// ```
fn parse_toml_deps(content: &str) -> Vec<(String, Vec<String>)> {
    let mut result = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments, section headers, blank lines.
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }

        let Some(eq_pos) = line.find('=') else {
            continue;
        };
        let name = line[..eq_pos].trim().to_string();
        let rest = line[eq_pos + 1..].trim();

        // Extract `deps = [...]`.
        let deps = if let Some(di) = rest.find("deps") {
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

        result.push((name, deps));
    }

    result
}
