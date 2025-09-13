use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{braced, parse_macro_input, Attribute, Fields, Ident, LitStr, Token, Type, Visibility};

struct LoggableVariant {
    error_message: LitStr,
    name: Ident,
    fields: Fields,
    level: syn::Expr,
}

struct LoggableInput {
    enum_name: Ident,
    variants: Vec<LoggableVariant>,
}

impl Parse for LoggableInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let enum_name = input.parse::<Ident>()?;

        let content;
        braced!(content in input);

        let mut variants = Vec::new();

        while !content.is_empty() {
            let attrs = content.call(Attribute::parse_outer)?;
            let error_attr = attrs
                .iter()
                .find(|attr| attr.path().is_ident("error"))
                .ok_or_else(|| content.error("Expected #[error(...)] attribute"))?;

            let error_message = error_attr.parse_args::<LitStr>()?;

            let name = content.parse::<Ident>()?;

            let fields = if content.peek(syn::token::Brace) {
                let field_content;
                braced!(field_content in content);

                let mut named_fields = syn::punctuated::Punctuated::new();
                while !field_content.is_empty() {
                    let field_name = field_content.parse::<Ident>()?;
                    field_content.parse::<Token![:]>()?;
                    let field_type = field_content.parse::<Type>()?;

                    named_fields.push(syn::Field {
                        attrs: vec![],
                        vis: Visibility::Inherited,
                        mutability: syn::FieldMutability::None,
                        ident: Some(field_name),
                        colon_token: Some(Default::default()),
                        ty: field_type,
                    });

                    if field_content.peek(Token![,]) {
                        field_content.parse::<Token![,]>()?;
                    }
                }

                Fields::Named(syn::FieldsNamed {
                    brace_token: Default::default(),
                    named: named_fields,
                })
            } else {
                Fields::Unit
            };

            content.parse::<Token![=>]>()?;
            let level = content.parse::<syn::Expr>()?;

            if content.peek(Token![,]) {
                content.parse::<Token![,]>()?;
            }

            variants.push(LoggableVariant {
                error_message,
                name,
                fields,
                level,
            });
        }

        Ok(LoggableInput {
            enum_name,
            variants,
        })
    }
}

pub fn loggable_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as LoggableInput);

    let enum_name = &input.enum_name;
    let variants = &input.variants;

    let enum_variants = variants.iter().map(|variant| {
        let name = &variant.name;
        let error_attr = &variant.error_message;
        let fields = &variant.fields;

        quote! {
            #[error(#error_attr)]
            #name #fields
        }
    });

    let level_match_arms = variants.iter().map(|variant| {
        let name = &variant.name;
        let level = &variant.level;
        let field_pattern = match &variant.fields {
            Fields::Unit => quote! {},
            Fields::Named(fields) => {
                let field_names = fields.named.iter().map(|f| &f.ident);
                quote! { { #(#field_names: _),* } }
            }
            Fields::Unnamed(_) => quote! { (..) },
        };

        quote! {
            Self::#name #field_pattern => #level
        }
    });

    quote! {
        #[allow(dead_code)]
        #[derive(Debug, Clone, thiserror::Error, serde::Serialize, serde::Deserialize)]
        pub enum #enum_name {
            #(#enum_variants,)*
        }

        impl #enum_name {
            #[allow(dead_code)]
            pub fn level(&self) -> tracing::Level {
                match self {
                    #(#level_match_arms,)*
                }
            }
        }
    }
        .into()
}
