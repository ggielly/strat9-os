//! Procedural macros for the component initialization system

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Register a function to be called when the component system is initialized.
///
/// You can specify the initialization stage by:
/// - `#[init_component]` or `#[init_component(bootstrap)]` - the **Bootstrap** stage
/// - `#[init_component(kthread)]` - the **Kthread** stage  
/// - `#[init_component(process)]` - the **Process** stage
///
/// # Example
///
/// ```rust,no_run
/// #[init_component]
/// fn init() -> Result<(), component::ComponentInitError> {
///     Ok(())
/// }
/// ```
#[proc_macro_attribute]
pub fn init_component(args: TokenStream, input: TokenStream) -> TokenStream {
    let stage = match args.to_string().as_str() {
        "" | "bootstrap" => quote! { Bootstrap },
        "kthread" => quote! { Kthread },
        "process" => quote! { Process },
        _ => panic!("Invalid argument for init_component. Use: bootstrap, kthread, or process"),
    };

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
                file!(),
                0, // Default priority, can be customized later
            );
    };

    TokenStream::from(expanded)
}
