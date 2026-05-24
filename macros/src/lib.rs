mod config;
mod error_enum;
mod fallible;
mod log;
mod loggable;
mod traceable;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn config_settings(attr: TokenStream, item: TokenStream) -> TokenStream {
    config::config_settings_impl(attr, item)
}

#[proc_macro]
pub fn fallible(input: TokenStream) -> TokenStream {
    fallible::fallible_impl(input)
}

#[proc_macro]
pub fn log(input: TokenStream) -> TokenStream {
    log::log_impl(input)
}

#[proc_macro]
pub fn loggable(input: TokenStream) -> TokenStream {
    loggable::loggable_impl(input)
}

#[proc_macro]
pub fn traceable(input: TokenStream) -> TokenStream {
    traceable::traceable_impl(input)
}
