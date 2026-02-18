//! Procedural macros for the component initialization system

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Register a function to be called when the component system is initialized.
///
/// You can specify the initialization stage and options:
/// - `#[init_component]` or `#[init_component(bootstrap)]` - Bootstrap stage (default)
/// - `#[init_component(kthread)]` - Kthread stage
/// - `#[init_component(process)]` - Process stage
/// - `#[init_component(bootstrap, priority = 1)]` - With custom priority
///
/// # Examples
///
/// ```rust,no_run
/// // Basic usage - default priority 0
/// #[init_component]
/// fn memory_init() -> Result<(), component::ComponentInitError> {
///     Ok(())
/// }
///
/// // With priority - lower number = earlier init
/// #[init_component(bootstrap, priority = 1)]
/// fn logger_init() -> Result<(), component::ComponentInitError> {
///     Ok(())
/// }
///
/// // Kthread stage
/// #[init_component(kthread, priority = 2)]
/// fn scheduler_init() -> Result<(), component::ComponentInitError> {
///     Ok(())
/// }
/// ```
#[proc_macro_attribute]
pub fn init_component(args: TokenStream, input: TokenStream) -> TokenStream {
    // Parse arguments: stage, priority = N
    let mut stage = quote! { Bootstrap };
    let mut priority: u32 = 0;

    let args_str = args.to_string();
    
    // Parse stage
    if !args_str.is_empty() {
        stage = match args_str.split(',').next().unwrap_or("").trim() {
            "" | "bootstrap" => quote! { Bootstrap },
            "kthread" => quote! { Kthread },
            "process" => quote! { Process },
            other => panic!("Invalid stage '{}'. Use: bootstrap, kthread, or process", other),
        };
    }

    // Parse priority if present
    if let Some(pos) = args_str.find("priority") {
        if let Some(eq_pos) = args_str[pos..].find('=') {
            let start = pos + eq_pos + 1;
            if let Some(end) = args_str[start..].find(|c: char| !c.is_numeric() && c != ' ') {
                let priority_str = args_str[start..start + end].trim();
                if let Ok(p) = priority_str.parse::<u32>() {
                    priority = p;
                }
            } else {
                let priority_str = args_str[start..].trim();
                if let Ok(p) = priority_str.parse::<u32>() {
                    priority = p;
                }
            }
        }
    }

    let function = parse_macro_input!(input as ItemFn);
    let function_name = &function.sig.ident;
    let function_vis = &function.vis;
    let function_sig = &function.sig;
    let function_block = &function.block;

    // Generate a unique static name based on function name and file location
    let static_name = quote::format_ident!("__COMPONENT_{}_{}", function_name, line!());

    let expanded = quote! {
        #function_vis #function_sig #function_block

        #[doc(hidden)]
        #[allow(non_upper_case_globals)]
        #[link_section = ".component_entries"]
        #[used]
        static #static_name: component::ComponentEntry =
            component::ComponentEntry::new(
                component::InitStage::#stage,
                #function_name,
                ::core::concat!(file!(), ":", ::core::stringify!(#function_name)),
                #priority,
            );
    };

    TokenStream::from(expanded)
}
