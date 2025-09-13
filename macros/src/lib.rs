mod log;
mod loggable;
mod traceable;

use proc_macro::TokenStream;

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
