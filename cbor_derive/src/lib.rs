//! Procedural macros to derive CBOR-friendly serde Serialize and Deserialize
//! traits for storing a `struct` as a CBOR `map`.
//! 
//! This is similar to
//! [minicbor_derive](https://docs.rs/minicbor-derive/0.12.0/minicbor_derive/index.html),
//! and makes message types similar to Protocol Buffers (ID-tagged fields).
//! 
//! Each `#[derive(CborMessage)]` on a `struct` makes an extra `${name}Dict`
//! type which contains a single `BTreeMap<u32, serde_cbor::Value>`. 
extern crate proc_macro2;
use proc_macro2::{Span, TokenStream};
extern crate quote;
extern crate syn;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Attribute, Data, DeriveInput, Error, Fields, GenericParam,
    Generics, Ident, Index, Meta, NestedMeta,
};

const CBOR_FIELD_ATTR: &str = "f";

#[proc_macro_derive(CborMessage, attributes(f))]
pub fn cbor_map(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;

    // Identifier for the BTreeMap container.
    // TODO: don't hard code this
    let d = Ident::new(&format!("{}Dict", name), Span::call_site());

    // Add a bound `T: HeapSize` to every type parameter T.
    // let generics = add_trait_bounds(input.generics);
    // let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // this generates an impl of the conversion code
    let dict_to_struct = to_struct(&input.data, &name);
    let struct_to_dict = to_dict(&input.data, &name);

    let expanded = quote! {
        // The generated impl.
        // impl #impl_generics TryFrom<#d> for #name #ty_generics #where_clause {

        // The underlying CBOR `map` used to represent the message.
        #[derive(Serialize, Deserialize, Debug)]
        struct #d {
            #[serde(flatten)]
            pub keys: BTreeMap<serde_cbor::Value, serde_cbor::Value>,
        }

        // Convert from $name to `map`
        impl From<#name> for #d {
            fn from(value: #name) -> Self {
                let mut keys = BTreeMap::new();
                #struct_to_dict
                #d { keys }
            }
        }
        
        // Convert `map` to $name
        impl TryFrom<#d> for #name {
            type Error = &'static str;
            fn try_from(mut raw: #d) -> Result<Self, Self::Error> {
                Ok(#dict_to_struct)
            }
        }

        // Convert bytes to $name
        impl TryFrom<&[u8]> for #name {
            type Error = &'static str;
            fn try_from(i: &[u8]) -> Result<Self, Self::Error> {
                serde_cbor::from_slice(&i).map_err(|e| {"cbor error"})
            }
        }
    };

    println!("expanded: {}", expanded.to_string());
    // Hand the output tokens back to the compiler.
    proc_macro::TokenStream::from(expanded)
}

fn add_trait_bounds(mut generics: Generics) -> Generics {
    for param in &mut generics.params {
        if let GenericParam::Type(ref mut type_param) = *param {
            // type_param.bounds.push(parse_quote!(heapsize::HeapSize));
        }
    }
    generics
}

fn to_struct(data: &Data, cls_name: &Ident) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        // println!("field = {:?}", name);

                        // Get the attribute's field tag
                        let a = f
                            .attrs
                            .iter()
                            .filter(|a| a.path.is_ident(CBOR_FIELD_ATTR))
                            .next()
                            .unwrap()
                            .parse_meta()
                            .unwrap();

                        match a {
                            Meta::List(l) => {
                                let k = &l.nested[0];
                                // println!("  attrs = {:?}", k);

                                // Inside here is each of the attributes of the struct
                                // The error code handling is still broken
                                // It would be nice to be able to point at some generic translator function
                                // Like we want something with TryFrom, except that only allows defining within that crate
                                // Also we essentially have some codegen here, and also need to provide a cbor library to go with it
                                quote_spanned! { f.span() =>
                                    #name: match raw.keys.remove(&#k) {
                                        Some(v) => match ConversionFunc::de(v) {
                                            Ok(d) => Some(d),
                                            Err(e) => return Err(e),
                                        },
                                        None => None,
                                    }
                                    // #name: raw.keys.remove(&#k).and_then(|v| {
                                    //     match ConversionFunc::de(v) {
                                    //         Ok(v) => v,
                                    //         Err(e) => return e,
                                    //     }
                                    // })
                                }
                            },
                            bad => unimplemented!(),
                        }
                    });
                    quote! {
                        #cls_name {
                            #( #recurse ,)*
                        }

                    }
                }
                _ => unimplemented!(),
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}

fn to_dict(data: &Data, cls_name: &Ident) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        // println!("field = {:?}", name);

                        // Get the field type attribute
                        let a = f
                            .attrs
                            .iter()
                            .filter(|a| a.path.is_ident(CBOR_FIELD_ATTR))
                            .next()
                            .unwrap()
                            .parse_meta()
                            .unwrap();

                        match a {
                            Meta::List(l) => {
                                let k = &l.nested[0];
                                // println!("  attrs = {:?}", k);

                                // Inside here is each of the attributes of the struct
                                quote_spanned! { f.span() =>
                                    value.#name.map(|v| {
                                        keys.insert(#k, ConversionFunc::ser(v));
                                    });
                                }
                            }
                            bad => unimplemented!(),
                        }
                    });
                    quote! {
                            #( #recurse )*
                    }
                }
                _ => unimplemented!(),
            }
        }
        Data::Enum(_) | Data::Union(_) => unimplemented!(),
    }
}
