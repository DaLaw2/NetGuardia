use std::collections::BTreeMap;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::{Fields, Ident, ItemStruct, LitBool, LitStr, Result, Token, Type};

// ── Attribute parsing ──────────────────────────────────────────────

struct StructAttr {
    default_section: Option<String>,
}

impl Parse for StructAttr {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut section = None;
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let val: LitStr = input.parse()?;
            if key == "section" {
                section = Some(val.value());
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(Self {
            default_section: section,
        })
    }
}

// ── Field model ────────────────────────────────────────────────────

enum ConfigField {
    Setting(SettingField),
    Flatten(FlattenField),
    MappedParent(MappedParent),
}

struct SettingField {
    ident: Ident,
    ty: Type,
    key: String,
    default: String,
    default_debug: Option<String>,
    section: Option<String>,
    api: bool,
}

struct FlattenField {
    ident: Ident,
    ty: Type,
}

struct MappedSetting {
    key: String,
    default: String,
    default_debug: Option<String>,
    parent: String,
    sub_field: String,
    section: Option<String>,
    api: bool,
}

struct MappedParent {
    ident: Ident,
    ty: Type,
    settings: Vec<MappedSetting>,
}

// ── Parsing ────────────────────────────────────────────────────────

fn parse_struct_mapped_settings(input: &mut ItemStruct, default_section: &Option<String>) -> Vec<MappedSetting> {
    let mut mapped = Vec::new();
    input.attrs.retain(|attr| {
        if !attr.path().is_ident("setting") {
            return true;
        }
        let mut key = None;
        let mut default = None;
        let mut default_debug = None;
        let mut path = None;
        let mut section = None;
        let mut api = true;

        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("key") {
                let val: LitStr = meta.value()?.parse()?;
                key = Some(val.value());
            } else if meta.path.is_ident("default") {
                let val: LitStr = meta.value()?.parse()?;
                default = Some(val.value());
            } else if meta.path.is_ident("default_debug") {
                let val: LitStr = meta.value()?.parse()?;
                default_debug = Some(val.value());
            } else if meta.path.is_ident("path") {
                let val: LitStr = meta.value()?.parse()?;
                path = Some(val.value());
            } else if meta.path.is_ident("section") {
                let val: LitStr = meta.value()?.parse()?;
                section = Some(val.value());
            } else if meta.path.is_ident("api") {
                let val: LitBool = meta.value()?.parse()?;
                api = val.value();
            }
            Ok(())
        });

        if let (Some(key), Some(default), Some(path)) = (key, default, path) {
            let (parent, sub_field) = path
                .split_once('.')
                .expect("#[setting] `path` must be `parent.sub_field`");
            mapped.push(MappedSetting {
                key,
                default,
                default_debug,
                parent: parent.to_string(),
                sub_field: sub_field.to_string(),
                section: section.or_else(|| default_section.clone()),
                api,
            });
            false
        } else {
            true
        }
    });
    mapped
}

fn parse_field(field: &mut syn::Field, default_section: &Option<String>) -> Option<ConfigField> {
    let idx = field.attrs.iter().position(|a| a.path().is_ident("setting"))?;
    let attr = field.attrs.remove(idx);

    let mut is_flatten = false;
    let mut key = None;
    let mut default = None;
    let mut default_debug = None;
    let mut section = None;
    let mut api = true;

    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("flatten") {
            is_flatten = true;
        } else if meta.path.is_ident("key") {
            let val: LitStr = meta.value()?.parse()?;
            key = Some(val.value());
        } else if meta.path.is_ident("default") {
            let val: LitStr = meta.value()?.parse()?;
            default = Some(val.value());
        } else if meta.path.is_ident("default_debug") {
            let val: LitStr = meta.value()?.parse()?;
            default_debug = Some(val.value());
        } else if meta.path.is_ident("section") {
            let val: LitStr = meta.value()?.parse()?;
            section = Some(val.value());
        } else if meta.path.is_ident("api") {
            let val: LitBool = meta.value()?.parse()?;
            api = val.value();
        }
        Ok(())
    })
    .unwrap_or_else(|e| panic!("invalid #[setting]: {e}"));

    let ident = field.ident.clone().expect("named field");
    let ty = field.ty.clone();

    if is_flatten {
        return Some(ConfigField::Flatten(FlattenField { ident, ty }));
    }

    Some(ConfigField::Setting(SettingField {
        ident,
        ty,
        key: key.expect("#[setting] requires `key`"),
        default: default.expect("#[setting] requires `default`"),
        default_debug,
        section: section.or_else(|| default_section.clone()),
        api,
    }))
}

// ── Type detection ─────────────────────────────────────────────────

fn is_type(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(tp) if tp.path.is_ident(name))
}

fn is_vec_string(ty: &Type) -> bool {
    if let Type::Path(tp) = ty
        && let Some(seg) = tp.path.segments.last()
    {
        return seg.ident == "Vec";
    }
    false
}

// ── Code generation: defaults() ────────────────────────────────────

fn make_default_val(ty: &Type, default: &str) -> TokenStream2 {
    if is_type(ty, "String") {
        quote! { #default.to_string() }
    } else if is_type(ty, "bool") {
        let val = default == "true" || default == "1";
        quote! { #val }
    } else if is_vec_string(ty) {
        if default.is_empty() {
            quote! { Vec::new() }
        } else {
            let items: Vec<&str> = default.split(',').map(|v| v.trim()).collect();
            quote! { vec![#(#items.to_string()),*] }
        }
    } else {
        // SAFETY: literal default, validated by tests
        quote! { #default.parse().unwrap() }
    }
}

fn gen_default(f: &SettingField) -> TokenStream2 {
    let ident = &f.ident;
    let ty = &f.ty;

    match &f.default_debug {
        Some(dbg) => {
            let release_val = make_default_val(ty, &f.default);
            let debug_val = make_default_val(ty, dbg);
            quote! { #ident: if cfg!(debug_assertions) { #debug_val } else { #release_val } }
        }
        None => {
            let val = make_default_val(ty, &f.default);
            quote! { #ident: #val }
        }
    }
}

fn gen_flatten_default(f: &FlattenField) -> TokenStream2 {
    let ident = &f.ident;
    let ty = &f.ty;
    quote! { #ident: #ty::defaults() }
}

fn gen_mapped_default(mp: &MappedParent) -> TokenStream2 {
    let ident = &mp.ident;
    let ty = &mp.ty;
    let sub_fields: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let sub = format_ident!("{}", s.sub_field);
            let val: TokenStream2 = match &s.default_debug {
                Some(dbg) => {
                    let release = &s.default;
                    // SAFETY: literal default, validated by tests
                    quote! { if cfg!(debug_assertions) { #dbg.parse().unwrap() } else { #release.parse().unwrap() } }
                }
                None => {
                    let default = &s.default;
                    // SAFETY: literal default, validated by tests
                    quote! { #default.parse().unwrap() }
                }
            };
            quote! { #sub: #val }
        })
        .collect();
    quote! { #ident: #ty { #(#sub_fields,)* } }
}

// ── Code generation: from_config_repo() ───────────────────────────────

fn gen_override(f: &SettingField) -> TokenStream2 {
    let ident = &f.ident;
    let key = &f.key;
    let ty = &f.ty;

    if is_type(ty, "String") {
        quote! {
            crate::domain::common::config::helpers::override_string_nonempty(
                &mut cfg.#ident, repo, #key,
            ).await?;
        }
    } else if is_type(ty, "bool") {
        quote! {
            crate::domain::common::config::helpers::override_bool(
                &mut cfg.#ident, repo, #key,
            ).await?;
        }
    } else if is_vec_string(ty) {
        quote! {
            crate::domain::common::config::helpers::override_csv(
                &mut cfg.#ident, repo, #key,
            ).await?;
        }
    } else {
        quote! {
            crate::domain::common::config::helpers::override_parsed(
                &mut cfg.#ident, repo, #key,
            ).await?;
        }
    }
}

fn gen_flatten_override(f: &FlattenField) -> TokenStream2 {
    let ident = &f.ident;
    let ty = &f.ty;
    quote! { cfg.#ident = #ty::from_config_repo(repo).await?; }
}

fn gen_mapped_overrides(mp: &MappedParent) -> TokenStream2 {
    let parent = &mp.ident;
    let calls: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let sub = format_ident!("{}", s.sub_field);
            let key = &s.key;
            quote! {
                crate::domain::common::config::helpers::override_parsed(
                    &mut cfg.#parent.#sub, repo, #key,
                ).await?;
            }
        })
        .collect();
    quote! { #(#calls)* }
}

// ── Code generation: seed_config_defaults() ───────────────────────────────

fn gen_seed(f: &SettingField) -> TokenStream2 {
    let key = &f.key;
    let default = &f.default;

    match &f.default_debug {
        Some(dbg) => quote! {
            crate::domain::common::config::helpers::seed_key(
                repo, #key,
                if cfg!(debug_assertions) { #dbg } else { #default },
            ).await?;
        },
        None => quote! {
            crate::domain::common::config::helpers::seed_key(repo, #key, #default).await?;
        },
    }
}

fn gen_flatten_seed(f: &FlattenField) -> TokenStream2 {
    let ty = &f.ty;
    quote! { #ty::seed_config_defaults(repo).await?; }
}

fn gen_mapped_seeds(mp: &MappedParent) -> TokenStream2 {
    let calls: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let key = &s.key;
            let default = &s.default;
            match &s.default_debug {
                Some(dbg) => quote! {
                    crate::domain::common::config::helpers::seed_key(
                        repo, #key,
                        if cfg!(debug_assertions) { #dbg } else { #default },
                    ).await?;
                },
                None => quote! {
                    crate::domain::common::config::helpers::seed_key(repo, #key, #default).await?;
                },
            }
        })
        .collect();
    quote! { #(#calls)* }
}

// ── Code generation: API_KEYS ──────────────────────────────────────

fn collect_api_keys(fields: &[ConfigField]) -> Vec<(&str, &str)> {
    let mut keys = Vec::new();
    for f in fields {
        match f {
            ConfigField::Setting(s) if s.api => {
                let sec = s.section.as_deref().unwrap_or("default");
                keys.push((sec, s.key.as_str()));
            }
            ConfigField::MappedParent(mp) => {
                for s in &mp.settings {
                    if s.api {
                        let sec = s.section.as_deref().unwrap_or("default");
                        keys.push((sec, s.key.as_str()));
                    }
                }
            }
            _ => {}
        }
    }
    keys
}

fn gen_keys_consts(fields: &[ConfigField]) -> TokenStream2 {
    let api_keys = collect_api_keys(fields);
    if api_keys.is_empty() {
        return quote! {};
    }

    let mut sections: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (sec, key) in &api_keys {
        sections.entry(sec).or_default().push(key);
    }

    let single = sections.len() == 1;
    sections
        .iter()
        .map(|(section, keys)| {
            let name = if single {
                format_ident!("API_KEYS")
            } else {
                format_ident!("{}_KEYS", section.to_uppercase())
            };
            quote! { pub const #name: &[&str] = &[#(#keys),*]; }
        })
        .collect()
}

// ── Code generation: api_values() ─────────────────────────────────

fn value_to_string_expr(ty: &Type, expr: TokenStream2) -> TokenStream2 {
    if is_type(ty, "String") {
        quote! { #expr.clone() }
    } else if is_vec_string(ty) {
        quote! { #expr.join(",") }
    } else {
        quote! { #expr.to_string() }
    }
}

fn gen_api_values(fields: &[ConfigField]) -> TokenStream2 {
    let entries: Vec<_> = fields
        .iter()
        .flat_map(|f| match f {
            ConfigField::Setting(s) if s.api => {
                let key = &s.key;
                let ident = &s.ident;
                let value = value_to_string_expr(&s.ty, quote! { self.#ident });
                vec![quote! { values.push((#key, #value)); }]
            }
            ConfigField::Flatten(f) => {
                let ident = &f.ident;
                vec![quote! { values.extend(self.#ident.api_values()); }]
            }
            ConfigField::MappedParent(mp) => mp
                .settings
                .iter()
                .filter(|s| s.api)
                .map(|s| {
                    let key = &s.key;
                    let parent = &mp.ident;
                    let sub = format_ident!("{}", s.sub_field);
                    quote! { values.push((#key, self.#parent.#sub.to_string())); }
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect();

    quote! {
        pub fn api_values(&self) -> Vec<(&'static str, String)> {
            let mut values = Vec::new();
            #(#entries)*
            values
        }
    }
}

// ── Entry point ────────────────────────────────────────────────────

pub fn config_settings_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let struct_attr = syn::parse_macro_input!(attr as StructAttr);
    let mut input = syn::parse_macro_input!(item as ItemStruct);

    let mapped_settings = parse_struct_mapped_settings(&mut input, &struct_attr.default_section);

    let mut mapped_groups: BTreeMap<String, Vec<MappedSetting>> = BTreeMap::new();
    for ms in mapped_settings {
        mapped_groups.entry(ms.parent.clone()).or_default().push(ms);
    }

    let fields = match &mut input.fields {
        Fields::Named(f) => f,
        _ => panic!("config_settings only supports named fields"),
    };

    let mut config_fields = Vec::new();
    for field in &mut fields.named {
        let field_name = field.ident.as_ref().expect("named field").to_string();

        if let Some(settings) = mapped_groups.remove(&field_name) {
            config_fields.push(ConfigField::MappedParent(MappedParent {
                ident: field.ident.clone().unwrap(),
                ty: field.ty.clone(),
                settings,
            }));
        } else if let Some(cf) = parse_field(field, &struct_attr.default_section) {
            config_fields.push(cf);
        }
    }

    let struct_name = &input.ident;
    let keys_consts = gen_keys_consts(&config_fields);
    let api_values = gen_api_values(&config_fields);

    let default_fields: Vec<_> = config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_default(s),
            ConfigField::Flatten(s) => gen_flatten_default(s),
            ConfigField::MappedParent(mp) => gen_mapped_default(mp),
        })
        .collect();

    let override_calls: Vec<_> = config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_override(s),
            ConfigField::Flatten(s) => gen_flatten_override(s),
            ConfigField::MappedParent(mp) => gen_mapped_overrides(mp),
        })
        .collect();

    let seed_calls: Vec<_> = config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_seed(s),
            ConfigField::Flatten(s) => gen_flatten_seed(s),
            ConfigField::MappedParent(mp) => gen_mapped_seeds(mp),
        })
        .collect();

    let expanded = quote! {
        #input

        impl #struct_name {
            #keys_consts
            #api_values

            pub fn defaults() -> Self {
                Self {
                    #(#default_fields,)*
                }
            }

            pub async fn from_config_repo(
                repo: &dyn crate::interface::config_repo::ConfigRepo,
            ) -> Result<Self, crate::domain::common::error::Error> {
                let mut cfg = Self::defaults();
                #(#override_calls)*
                Ok(cfg)
            }

            pub async fn seed_config_defaults(
                repo: &dyn crate::interface::config_repo::ConfigRepo,
            ) -> Result<(), crate::domain::common::error::Error> {
                #(#seed_calls)*
                Ok(())
            }
        }
    };

    TokenStream::from(expanded)
}
