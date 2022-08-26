extern crate proc_macro2;
use proc_macro2::{TokenStream, Span};
extern crate quote;
extern crate syn;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{
    parse_macro_input, parse_quote, Data, DeriveInput, Fields, GenericParam, Generics, Ident, Index, Meta, Error, Attribute, NestedMeta,
};

/*
#[proc_macro_derive(CborMessage)]
pub fn derive_cbor_message_fn(item: TokenStream) -> TokenStream {
    println!("Derive item: \"{}\"", item.to_string());
    "fn cbor() -> bool { true }".parse().unwrap()
}
*/

// fn iterate_stream(s: TokenStream, depth: usize) {
//     let pad = " ".repeat(depth);
//     for i in s {
//         match i {
//             Group(g) => {
//                 println!("{}iterate_stream::Group = ", pad);
//                 iterate_stream(g.stream(), depth + 2);
//             }
//             _ => {
//                 println!("{}iterate_stream::item = {:?}", pad, i)
//             }
//         }
//     }

// }

#[proc_macro_derive(CborMessage, attributes(cbor_field))]
pub fn cbor_map(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    // Parse the input tokens into a syntax tree.
    let input = parse_macro_input!(input as DeriveInput);

    // Used in the quasi-quotation below as `#name`.
    let name = input.ident;
    // TODO: don't hard code this
    let d = Ident::new(&format!("{}Dict", name), Span::call_site());

    // Add a bound `T: HeapSize` to every type parameter T.
    let generics = add_trait_bounds(input.generics);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // this generates an impl of the conversion code
    let dict_to_struct = heap_size_sum(&input.data, &name);
    let struct_to_dict = to_dict(&input.data, &name);

    let expanded = quote! {
        // The generated impl.
        // impl #impl_generics TryFrom<#d> for #name #ty_generics #where_clause {

        #[derive(Serialize, Deserialize, Debug)]
        struct #d {
            #[serde(flatten)]
            pub keys: BTreeMap<u32, serde_cbor::Value>,
        }

        impl From<#name> for #d {
            fn from(value: #name) -> Self {
                let mut keys = BTreeMap::new();
                #struct_to_dict
                #d { keys }
            }
        }

        impl TryFrom<#d> for #name {
            type Error = &'static str;
            fn try_from(mut raw: #d) -> Result<Self, Self::Error> {
                Ok(#dict_to_struct)
            }
        }

        impl TryFrom<&[u8]> for #name {
            type Error = ();

            fn try_from(i: &[u8]) -> Result<Self, Self::Error> {
                serde_cbor::from_slice(&i).map_err(|e| {
                    error!("deserialise: {:?}", e);
                    ()
                })
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


// Generate an expression to sum up the heap size of each field.
fn heap_size_sum(data: &Data, cls_name: &Ident) -> TokenStream {
    match *data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    // IGNORE THIS BIT
                    // Expands to an expression like
                    //
                    //     0 + self.x.heap_size() + self.y.heap_size() + self.z.heap_size()
                    //
                    // but using fully qualified function call syntax.
                    //
                    // We take some care to use the span of each `syn::Field` as
                    // the span of the corresponding `heap_size_of_children`
                    // call. This way if one of the field types does not
                    // implement `HeapSize` then the compiler's error message
                    // underlines which field it is. An example is shown in the
                    // readme of the parent directory.

                    // ACTUAL CODE
                    let recurse = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        // println!("field = {:?}", name);

                        let a = f.attrs.iter().filter(
                            |a| a.path.is_ident("cbor_field")
                        ).next().unwrap().parse_meta().unwrap();

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
                                    #name: raw.keys.remove(&#k).and_then(|v| ConversionFunc::conv(v, #k))
                                }
                            },
                            bad => unimplemented!(),
                        }
                        

                        //if a.len() != 1 {
                        //    panic!("oops, need exactly 1 param for {:?}", name);
                        //}

                        // let key = &a[0].unwrap();
                        
                        // quote_spanned! {f.span()=>
                        //     //
                        // // 1
                        //     // heapsize::HeapSize::heap_size_of_children(&self.#name)
                        // }
                    });
                    quote! {
                        #cls_name {
                            #( #recurse ,)*
                        }
                        
                    }
                }
                Fields::Unnamed(ref fields) => unimplemented!(),

                // {
                //     // Expands to an expression like
                //     //
                //     //     0 + self.0.heap_size() + self.1.heap_size() + self.2.heap_size()
                //     let recurse = fields.unnamed.iter().enumerate().map(|(i, f)| {
                //         let index = Index::from(i);
                //         quote_spanned! {f.span()=>
                //             heapsize::HeapSize::heap_size_of_children(&self.#index)
                //         }
                //     });
                //     quote! {
                //         0 #(+ #recurse)*
                //     }
                // }
                Fields::Unit => {
                    // Unit structs cannot own more than 0 bytes of heap memory.
                    quote!(0)
                }
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

                        let a = f.attrs.iter().filter(
                            |a| a.path.is_ident("cbor_field")
                        ).next().unwrap().parse_meta().unwrap();

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
                                    value.#name.map(|v| {
                                        keys.insert(#k, ConversionFunc::rev(v));
                                    });
                                }
                            },
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
