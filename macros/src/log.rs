use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{parse_macro_input, Expr, Token};

struct LogInput {
    error: Expr,
    debug_info: Option<Expr>,
}

impl Parse for LogInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let error = input.parse::<Expr>()?;

        let debug_info = if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
            Some(input.parse::<Expr>()?)
        } else {
            None
        };

        Ok(LogInput { error, debug_info })
    }
}

pub fn log_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LogInput);

    let error_expr = &input.error;

    if let Some(debug_info) = &input.debug_info {
        quote! {
            {
                let error = #error_expr;
                let level = error.level();
                let message = error.to_string();
                let debug_info = #debug_info;

                match level {
                    tracing::Level::ERROR => tracing::error!(message = %message, debug = ?debug_info),
                    tracing::Level::WARN => tracing::warn!(message = %message, debug = ?debug_info),
                    tracing::Level::INFO => tracing::info!(message = %message, debug = ?debug_info),
                    tracing::Level::DEBUG => tracing::debug!(message = %message, debug = ?debug_info),
                    tracing::Level::TRACE => tracing::trace!(message = %message, debug = ?debug_info),
                }
            }
        }
    } else {
        quote! {
            {
                let error = #error_expr;
                let level = error.level();
                let message = error.to_string();

                match level {
                    tracing::Level::ERROR => tracing::error!("{}", message),
                    tracing::Level::WARN => tracing::warn!("{}", message),
                    tracing::Level::INFO => tracing::info!("{}", message),
                    tracing::Level::DEBUG => tracing::debug!("{}", message),
                    tracing::Level::TRACE => tracing::trace!("{}", message),
                }
            }
        }
    }
        .into()
}
