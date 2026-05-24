use std::collections::BTreeMap;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::{Error, Fields, Ident, ItemStruct, LitBool, LitStr, Result, Token, Type};

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

fn parse_struct_mapped_settings(
    input: &mut ItemStruct,
    default_section: &Option<String>,
) -> Result<Vec<MappedSetting>> {
    let mut mapped = Vec::new();
    let mut retained = Vec::new();
    for attr in input.attrs.drain(..) {
        if !attr.path().is_ident("setting") {
            retained.push(attr);
            continue;
        }
        let mut key = None;
        let mut default = None;
        let mut default_debug = None;
        let mut path = None;
        let mut section = None;
        let mut api = true;

        attr.parse_nested_meta(|meta| {
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
        })?;

        if let (Some(key), Some(default), Some(path)) = (key, default, path) {
            let (parent, sub_field) = path
                .split_once('.')
                .ok_or_else(|| Error::new(attr.span(), "#[setting] `path` must be `parent.sub_field`"))?;
            mapped.push(MappedSetting {
                key,
                default,
                default_debug,
                parent: parent.to_string(),
                sub_field: sub_field.to_string(),
                section: section.or_else(|| default_section.clone()),
                api,
            });
        } else {
            retained.push(attr);
        }
    }
    input.attrs = retained;
    Ok(mapped)
}

fn parse_field(field: &mut syn::Field, default_section: &Option<String>) -> Result<Option<ConfigField>> {
    let Some(idx) = field.attrs.iter().position(|a| a.path().is_ident("setting")) else {
        return Ok(None);
    };
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
    })?;

    let ident = field
        .ident
        .clone()
        .ok_or_else(|| Error::new(field.span(), "#[setting] only supports named fields"))?;
    let ty = field.ty.clone();

    if is_flatten {
        return Ok(Some(ConfigField::Flatten(FlattenField { ident, ty })));
    }

    let key = key.ok_or_else(|| Error::new(attr.span(), "#[setting] requires `key`"))?;
    let default = default.ok_or_else(|| Error::new(attr.span(), "#[setting] requires `default`"))?;

    Ok(Some(ConfigField::Setting(SettingField {
        ident,
        ty,
        key,
        default,
        default_debug,
        section: section.or_else(|| default_section.clone()),
        api,
    })))
}

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

fn parse_default_tokens(ty: &Type, default: &str) -> Result<TokenStream2> {
    default.parse::<TokenStream2>().map_err(|err| {
        Error::new(
            ty.span(),
            format!("invalid #[setting] default literal `{default}`: {err}"),
        )
    })
}

fn make_default_val(ty: &Type, default: &str) -> Result<TokenStream2> {
    if is_type(ty, "String") {
        Ok(quote! { #default.to_string() })
    } else if is_type(ty, "bool") {
        let val = default == "true" || default == "1";
        Ok(quote! { #val })
    } else if is_vec_string(ty) {
        if default.is_empty() {
            Ok(quote! { Vec::new() })
        } else {
            let items: Vec<&str> = default.split(',').map(|v| v.trim()).collect();
            Ok(quote! { vec![#(#items.to_string()),*] })
        }
    } else {
        let value = parse_default_tokens(ty, default)?;
        Ok(quote! { #value })
    }
}

fn gen_default(f: &SettingField) -> Result<TokenStream2> {
    let ident = &f.ident;
    let ty = &f.ty;

    match &f.default_debug {
        Some(dbg) => {
            let release_val = make_default_val(ty, &f.default)?;
            let debug_val = make_default_val(ty, dbg)?;
            Ok(quote! { #ident: if cfg!(debug_assertions) { #debug_val } else { #release_val } })
        }
        None => {
            let val = make_default_val(ty, &f.default)?;
            Ok(quote! { #ident: #val })
        }
    }
}

fn gen_flatten_default(f: &FlattenField) -> TokenStream2 {
    let ident = &f.ident;
    let ty = &f.ty;
    quote! { #ident: #ty::defaults() }
}

fn gen_mapped_default(mp: &MappedParent) -> Result<TokenStream2> {
    let ident = &mp.ident;
    let ty = &mp.ty;
    let sub_fields: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let sub = format_ident!("{}", s.sub_field);
            let val: TokenStream2 = match &s.default_debug {
                Some(dbg) => {
                    let debug = parse_default_tokens(&mp.ty, dbg)?;
                    let release = parse_default_tokens(&mp.ty, &s.default)?;
                    quote! { if cfg!(debug_assertions) { #debug } else { #release } }
                }
                None => parse_default_tokens(&mp.ty, &s.default)?,
            };
            Ok(quote! { #sub: #val })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(quote! { #ident: #ty { #(#sub_fields,)* } })
}

fn gen_apply_value(f: &SettingField) -> TokenStream2 {
    let ident = &f.ident;
    let key = &f.key;
    let ty = &f.ty;

    if is_type(ty, "String") {
        quote! {
            if let Some(v) = values.get(#key)
                && !v.is_empty()
            {
                self.#ident = v.clone();
            }
        }
    } else if is_type(ty, "bool") {
        quote! {
            if let Some(v) = values.get(#key) {
                self.#ident = v == "true" || v == "1";
            }
        }
    } else if is_vec_string(ty) {
        quote! {
            if let Some(v) = values.get(#key) {
                self.#ident = if v.is_empty() {
                    Vec::new()
                } else {
                    v.split(',').map(|s| s.trim().to_string()).collect()
                };
            }
        }
    } else {
        quote! {
            if let Some(v) = values.get(#key)
                && let Ok(parsed) = v.parse()
            {
                self.#ident = parsed;
            }
        }
    }
}

fn gen_flatten_apply(f: &FlattenField) -> TokenStream2 {
    let ident = &f.ident;
    quote! { self.#ident.apply_config_values(values); }
}

fn gen_mapped_apply(mp: &MappedParent) -> TokenStream2 {
    let parent = &mp.ident;
    let calls: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let sub = format_ident!("{}", s.sub_field);
            let key = &s.key;
            quote! {
                if let Some(v) = values.get(#key)
                    && let Ok(parsed) = v.parse()
                {
                    self.#parent.#sub = parsed;
                }
            }
        })
        .collect();
    quote! { #(#calls)* }
}

fn gen_default_setting(f: &SettingField) -> TokenStream2 {
    let key = &f.key;
    let default = &f.default;

    match &f.default_debug {
        Some(dbg) => quote! {
            settings.push((#key, if cfg!(debug_assertions) { #dbg.to_string() } else { #default.to_string() }));
        },
        None => quote! {
            settings.push((#key, #default.to_string()));
        },
    }
}

fn gen_flatten_default_settings(f: &FlattenField) -> TokenStream2 {
    let ty = &f.ty;
    quote! { settings.extend(#ty::default_settings()); }
}

fn gen_mapped_default_settings(mp: &MappedParent) -> TokenStream2 {
    let calls: Vec<_> = mp
        .settings
        .iter()
        .map(|s| {
            let key = &s.key;
            let default = &s.default;
            match &s.default_debug {
                Some(dbg) => quote! {
                    settings.push((#key, if cfg!(debug_assertions) { #dbg.to_string() } else { #default.to_string() }));
                },
                None => quote! {
                    settings.push((#key, #default.to_string()));
                },
            }
        })
        .collect();
    quote! { #(#calls)* }
}

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

pub fn config_settings_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let struct_attr = syn::parse_macro_input!(attr as StructAttr);
    let mut input = syn::parse_macro_input!(item as ItemStruct);

    let mapped_settings = match parse_struct_mapped_settings(&mut input, &struct_attr.default_section) {
        Ok(settings) => settings,
        Err(err) => return err.to_compile_error().into(),
    };

    let mut mapped_groups: BTreeMap<String, Vec<MappedSetting>> = BTreeMap::new();
    for ms in mapped_settings {
        mapped_groups.entry(ms.parent.clone()).or_default().push(ms);
    }

    let fields = match &mut input.fields {
        Fields::Named(f) => f,
        _ => {
            return Error::new(input.span(), "config_settings only supports named fields")
                .to_compile_error()
                .into();
        }
    };

    let mut config_fields = Vec::new();
    for field in &mut fields.named {
        let Some(field_ident) = field.ident.clone() else {
            return Error::new(field.span(), "config_settings only supports named fields")
                .to_compile_error()
                .into();
        };
        let field_name = field_ident.to_string();

        if let Some(settings) = mapped_groups.remove(&field_name) {
            config_fields.push(ConfigField::MappedParent(MappedParent {
                ident: field_ident,
                ty: field.ty.clone(),
                settings,
            }));
        } else {
            match parse_field(field, &struct_attr.default_section) {
                Ok(Some(cf)) => config_fields.push(cf),
                Ok(None) => {}
                Err(err) => return err.to_compile_error().into(),
            }
        }
    }

    let struct_name = &input.ident;
    let keys_consts = gen_keys_consts(&config_fields);
    let api_values = gen_api_values(&config_fields);

    let default_fields: Vec<_> = match config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_default(s),
            ConfigField::Flatten(s) => Ok(gen_flatten_default(s)),
            ConfigField::MappedParent(mp) => gen_mapped_default(mp),
        })
        .collect::<Result<Vec<_>>>()
    {
        Ok(fields) => fields,
        Err(err) => return err.to_compile_error().into(),
    };

    let apply_calls: Vec<_> = config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_apply_value(s),
            ConfigField::Flatten(s) => gen_flatten_apply(s),
            ConfigField::MappedParent(mp) => gen_mapped_apply(mp),
        })
        .collect();

    let default_setting_calls: Vec<_> = config_fields
        .iter()
        .map(|f| match f {
            ConfigField::Setting(s) => gen_default_setting(s),
            ConfigField::Flatten(s) => gen_flatten_default_settings(s),
            ConfigField::MappedParent(mp) => gen_mapped_default_settings(mp),
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

            pub fn from_config_values(values: &super::ConfigValues) -> Self {
                let mut cfg = Self::defaults();
                cfg.apply_config_values(values);
                cfg
            }

            pub fn apply_config_values(&mut self, values: &super::ConfigValues) {
                #(#apply_calls)*
            }

            pub fn default_settings() -> Vec<(&'static str, String)> {
                let mut settings = Vec::new();
                #(#default_setting_calls)*
                settings
            }
        }
    };

    TokenStream::from(expanded)
}
