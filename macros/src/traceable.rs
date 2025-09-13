use proc_macro::TokenStream;

use crate::error_enum;

pub fn traceable_impl(input: TokenStream) -> TokenStream {
    error_enum::generate_error_enum(input, false)
}
