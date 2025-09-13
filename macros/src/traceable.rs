use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream}, parse_macro_input, spanned::Spanned, Attribute, Error, Expr, Ident, LitStr,
    Result,
    Token,
    Type,
};

struct ErrorVariant {
    attributes: Vec<Attribute>,
    error_msg: LitStr,
    name: Ident,
    fields: Vec<(Ident, Type)>,
    level: Expr,
}

impl ErrorVariant {
    fn has_no_source(&self) -> bool {
        self.attributes
            .iter()
            .any(|attr| attr.path().is_ident("no_source"))
    }

    fn should_generate_constructor(&self) -> bool {
        if self.has_no_source() {
            !self.fields.is_empty()
        } else {
            true
        }
    }
}

struct TraceableInput {
    enum_name: Ident,
    variants: Vec<ErrorVariant>,
}

impl Parse for TraceableInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let enum_name = input.parse::<Ident>()?;

        let content;
        syn::braced!(content in input);

        let mut variants = Vec::new();

        while !content.is_empty() {
            let mut attributes = Vec::new();

            while content.peek(Token![#]) {
                attributes.push(content.call(Attribute::parse_outer)?);
            }

            let attributes: Vec<_> = attributes.into_iter().flatten().collect();

            let error_attr = attributes
                .iter()
                .find(|attr| attr.path().is_ident("error"))
                .ok_or_else(|| Error::new(content.span(), "Missing #[error] attribute"))?;

            let error_msg = match &error_attr.meta {
                syn::Meta::List(list) => syn::parse2::<LitStr>(list.tokens.clone())?,
                _ => {
                    return Err(Error::new(
                        error_attr.span(),
                        "Invalid error attribute format",
                    ));
                }
            };

            let name = content.parse::<Ident>()?;

            let mut fields = Vec::new();
            if content.peek(syn::token::Brace) {
                let fields_content;
                syn::braced!(fields_content in content);

                while !fields_content.is_empty() {
                    let field_name = fields_content.parse::<Ident>()?;
                    fields_content.parse::<Token![:]>()?;
                    let field_type = fields_content.parse::<Type>()?;
                    fields.push((field_name, field_type));

                    if !fields_content.is_empty() {
                        fields_content.parse::<Token![,]>()?;
                    }
                }
            }

            content.parse::<Token![=>]>()?;
            let level = content.parse::<Expr>()?;

            if !content.is_empty() {
                content.parse::<Token![,]>()?;
            }

            variants.push(ErrorVariant {
                attributes,
                error_msg,
                name,
                fields,
                level,
            });
        }

        Ok(TraceableInput {
            enum_name,
            variants,
        })
    }
}

pub fn traceable_impl(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as TraceableInput);

    let enum_name = &input.enum_name;
    let variants = &input.variants;

    let enum_variants = variants.iter().map(|variant| {
        let name = &variant.name;
        let error_msg = &variant.error_msg;
        let fields = &variant.fields;

        let field_definitions = fields.iter().map(|(name, ty)| {
            quote! { #name: #ty }
        });

        if variant.has_no_source() {
            if variant.fields.is_empty() {
                quote! {
                    #[error(#error_msg)]
                    #name
                }
            } else {
                quote! {
                    #[error(#error_msg)]
                    #name { #(#field_definitions,)* }
                }
            }
        } else {
            quote! {
                #[error(#error_msg)]
                #name {
                    #(#field_definitions,)*
                    err: String
                }
            }
        }
    });

    let level_match_arms = variants.iter().map(|variant| {
        let name = &variant.name;
        let level = &variant.level;

        if variant.has_no_source() {
            if variant.fields.is_empty() {
                quote! {
                    Self::#name => #level
                }
            } else {
                quote! {
                    Self::#name { .. } => #level
                }
            }
        } else {
            quote! {
                Self::#name { err: _, .. } => #level
            }
        }
    });

    let constructors = variants.iter().filter_map(|variant| {
        if !variant.should_generate_constructor() {
            return None;
        }

        let name = &variant.name;
        let fields = &variant.fields;

        let params = fields.iter().map(|(field_name, field_type)| {
            quote! { #field_name: impl Into<#field_type> }
        });

        let field_assignments = fields.iter().map(|(field_name, _)| {
            quote! { #field_name: #field_name.into() }
        });

        if variant.has_no_source() {
            Some(quote! {
                #[allow(non_snake_case)]
                pub fn #name(#(#params),*) -> Self {
                    Self::#name {
                        #(#field_assignments,)*
                    }
                }
            })
        } else {
            Some(quote! {
                #[allow(non_snake_case)]
                pub fn #name(#(#params,)* source: impl std::fmt::Display) -> Self {
                    Self::#name {
                        #(#field_assignments,)*
                        err: source.to_string()
                    }
                }
            })
        }
    });

    let expanded = quote! {
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

            #(#constructors)*
        }
    };

    TokenStream::from(expanded)
}
