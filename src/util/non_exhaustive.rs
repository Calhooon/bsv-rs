// The module's doc is on its declaration in `src/util/mod.rs`: this file holds
// no inner attribute, so the doc tests below `include!` it whole and run the
// macros the crate runs (#819's third fold).

/// The pattern suffix of a variant with named fields.
#[allow(unused_macros)]
macro_rules! non_exhaustive_named {
    ($($fields:tt)*) => {
        " { .. }"
    };
}

/// The pattern suffix of a tuple variant.
#[allow(unused_macros)]
macro_rules! non_exhaustive_unnamed {
    ($($fields:tt)*) => {
        "(..)"
    };
}

/// The `compile_fail` match `non_exhaustive_enum!` writes into an enum's doc:
/// one arm per variant and no wildcard, so the attribute is the only thing
/// left for it to fail on. Held by what it writes (#819's third fold):
///
/// ```
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// # fn main() {
/// let block = util::non_exhaustive::non_exhaustive_fail_block!(
///     path = bsv_rs::sample::Sample;
///     Unit, Tuple(u8, u16), Named { a: u8 }
/// );
/// assert_eq!(
///     block,
///     concat!(
///         " ```compile_fail,E0004\n",
///         " fn every_variant(value: bsv_rs::sample::Sample) {\n",
///         "     match value {\n",
///         "         bsv_rs::sample::Sample::Unit => {}\n",
///         "         bsv_rs::sample::Sample::Tuple(..) => {}\n",
///         "         bsv_rs::sample::Sample::Named { .. } => {}\n",
///         "     }\n",
///         " }\n",
///         " ```",
///     )
/// );
/// # }
/// ```
#[allow(unused_macros)]
macro_rules! non_exhaustive_fail_block {
    (
        path = $path:path;
        $( $variant:ident $({ $($named:tt)* })? $(( $($unnamed:tt)* ))? ),* $(,)?
    ) => {
        ::core::concat!(
            " ```compile_fail,E0004\n",
            " fn every_variant(value: ", ::core::stringify!($path), ") {\n",
            "     match value {\n",
            $(
                "         ", ::core::stringify!($path), "::", ::core::stringify!($variant)
                $(, $crate::util::non_exhaustive::non_exhaustive_named!($($named)*))?
                $(, $crate::util::non_exhaustive::non_exhaustive_unnamed!($($unnamed)*))?,
                " => {}\n",
            )*
            "     }\n",
            " }\n",
            " ```"
        )
    };
}

/// The compiling twin `non_exhaustive_enum!` writes beside the `compile_fail`
/// match: the same arms, hidden, then a wildcard. Held by what it writes:
///
/// ```
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// # fn main() {
/// let block = util::non_exhaustive::non_exhaustive_twin_block!(
///     path = bsv_rs::sample::Sample;
///     Unit, Tuple(u8, u16), Named { a: u8 }
/// );
/// assert_eq!(
///     block,
///     concat!(
///         " ```\n",
///         " fn every_variant(value: bsv_rs::sample::Sample) {\n",
///         "     match value {\n",
///         "         // every variant, as above, then:\n",
///         " #         bsv_rs::sample::Sample::Unit => {}\n",
///         " #         bsv_rs::sample::Sample::Tuple(..) => {}\n",
///         " #         bsv_rs::sample::Sample::Named { .. } => {}\n",
///         "         _ => {}\n",
///         "     }\n",
///         " }\n",
///         " ```",
///     )
/// );
/// # }
/// ```
#[allow(unused_macros)]
macro_rules! non_exhaustive_twin_block {
    (
        path = $path:path;
        $( $variant:ident $({ $($named:tt)* })? $(( $($unnamed:tt)* ))? ),* $(,)?
    ) => {
        ::core::concat!(
            " ```\n",
            " fn every_variant(value: ", ::core::stringify!($path), ") {\n",
            "     match value {\n",
            "         // every variant, as above, then:\n",
            $(
                " #         ", ::core::stringify!($path), "::", ::core::stringify!($variant)
                $(, $crate::util::non_exhaustive::non_exhaustive_named!($($named)*))?
                $(, $crate::util::non_exhaustive::non_exhaustive_unnamed!($($unnamed)*))?,
                " => {}\n",
            )*
            "         _ => {}\n",
            "     }\n",
            " }\n",
            " ```"
        )
    };
}

/// An enum's `#[non_exhaustive]` pinned by a doc test written from its
/// definition (#819's fold). `path` is the type's public path as a doc test
/// outside the crate names it, `bsv_rs::` and the rest.
///
/// The macro passes the enum through token for token and appends the two
/// blocks above to its doc. It also asserts, by the compiler, that `path`
/// names this type (#819's third fold): a function from the type to the
/// path's type must compile (`bsv_rs` is the crate's own name inside it,
/// `extern crate self as bsv_rs` in `src/lib.rs`), so a pin naming
/// another type of the same name through an alias or a re-export fails the
/// build. Under `cfg(test)` it gives the type `VARIANT_NAMES`, the variants'
/// names in the definition's order, for an in-crate test of a hand-kept list.
///
/// The type-identity assertion fails to compile when the path names another
/// type:
///
/// ```compile_fail,E0308
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// pub mod sample {
///     pub enum Other { One }
///     crate::util::non_exhaustive::non_exhaustive_enum! {
///         path = crate::sample::Other;
///     pub enum Sample { One }
///     }
/// }
/// # fn main() {}
/// ```
///
/// and compiles when it names this one:
///
/// ```
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// pub mod sample {
///     pub enum Other { One }
///     crate::util::non_exhaustive::non_exhaustive_enum! {
///         path = crate::sample::Sample;
///     pub enum Sample { One }
///     }
/// }
/// # fn main() {}
/// ```
///
/// What it cannot hold: a variant under `cfg` (its arm would be written
/// whether or not the variant exists; `tests/arch_non_exhaustive_pins_819.rs`
/// refuses one inside an invocation).
#[allow(unused_macros)]
macro_rules! non_exhaustive_enum {
    (
        path = $path:path;
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({ $($named:tt)* })? $(( $($unnamed:tt)* ))?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[doc = ""]
        #[doc = " A later variant is additive: a `match` outside this crate ends in a"]
        #[doc = " wildcard arm, and one naming every variant without it does not compile."]
        #[doc = " The block is written from the definition, so it names every variant:"]
        #[doc = ""]
        #[doc = $crate::util::non_exhaustive::non_exhaustive_fail_block!(
            path = $path;
            $( $variant $({ $($named)* })? $(( $($unnamed)* ))? ),*
        )]
        #[doc = ""]
        #[doc = " With the wildcard arm it compiles:"]
        #[doc = ""]
        #[doc = $crate::util::non_exhaustive::non_exhaustive_twin_block!(
            path = $path;
            $( $variant $({ $($named)* })? $(( $($unnamed)* ))? ),*
        )]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($named)* })? $(( $($unnamed)* ))?
            ),*
        }

        const _: fn($name) -> $path = |value| value;

        #[cfg(test)]
        #[allow(dead_code)]
        impl $name {
            /// The variants' names, in the definition's order.
            pub(crate) const VARIANT_NAMES: &'static [&'static ::core::primitive::str] =
                &[$(::core::stringify!($variant)),*];
        }
    };
}

/// A pinned struct implements no `Drop`, and its pin's path names it, both
/// held by the compiler (#819's second and third folds). A functional update
/// of a `Drop` type is refused for that reason alone (E0509), so the struct's
/// `compile_fail` block would read `ok` with the `#[non_exhaustive]` removed;
/// with this assertion beside the struct an `impl Drop` for it, in any file
/// the build compiles, fails the crate's build, while this macro keeps its
/// one general arm (an arm for one type's name ahead of it would pass that
/// type: this file is pinned whole by its digest and each macro to one arm,
/// #819's fourth fold, in `tests/arch_non_exhaustive_pins_819.rs`) and its
/// bounds name `::core::ops::Drop` and `::core::marker::Sized` (#819's fifth
/// fold: every path in these macros' bodies is absolute, so no `use` at a
/// call site, a `Drop` alias among them, changes what they mean). The second
/// argument is the pin's path (`bsv_rs` the crate's own name inside it): a
/// function from the type to the path's type must compile, so a pin naming
/// another type of the same name fails the build.
///
/// The form is the static-assertion idiom for a trait not implemented: the
/// method is found through one of two blanket impls, ambiguous when the
/// second, bounded on `Drop`, also applies. `T: Drop` holds only for a type
/// with its own `impl Drop`, never for drop glue (a `String` field).
/// `tests/arch_non_exhaustive_pins_819.rs` requires the invocation directly
/// after every pinned struct, naming its pin's path.
///
/// Held by what it does: on a type with its own `Drop` it fails to compile
///
/// ```compile_fail,E0283
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// pub mod sample {
///     pub struct Held {
///         pub one: String,
///     }
///     impl Drop for Held {
///         fn drop(&mut self) {}
///     }
///     crate::util::non_exhaustive::assert_no_drop!(Held, crate::sample::Held);
/// }
/// # fn main() {}
/// ```
///
/// on a pin's path naming another type it fails to compile
///
/// ```compile_fail,E0308
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// pub mod sample {
///     pub struct Held {
///         pub one: String,
///     }
///     pub struct Other;
///     crate::util::non_exhaustive::assert_no_drop!(Held, crate::sample::Other);
/// }
/// # fn main() {}
/// ```
///
/// and on a type without one, named by its own path, it compiles:
///
/// ```
/// # mod util { pub mod non_exhaustive {
/// #     include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/util/non_exhaustive.rs"));
/// # } }
/// pub mod sample {
///     pub struct Held {
///         pub one: String,
///     }
///     pub struct Other;
///     crate::util::non_exhaustive::assert_no_drop!(Held, crate::sample::Held);
/// }
/// # fn main() {}
/// ```
#[allow(unused_macros)]
macro_rules! assert_no_drop {
    ($name:ident, $path:path) => {
        const _: fn() = || {
            trait AmbiguousIfDrop<A> {
                fn some_item() {}
            }
            impl<T: ?::core::marker::Sized> AmbiguousIfDrop<()> for T {}
            #[allow(dead_code)]
            struct ImplementsDrop;
            #[allow(drop_bounds)]
            impl<T: ?::core::marker::Sized + ::core::ops::Drop> AmbiguousIfDrop<ImplementsDrop> for T {}
            let _ = <$name as AmbiguousIfDrop<_>>::some_item;
        };
        const _: fn($name) -> $path = |value| value;
    };
}

// Unused under a feature set that compiles none of the enums.
#[allow(unused_imports)]
pub(crate) use {
    assert_no_drop, non_exhaustive_enum, non_exhaustive_fail_block, non_exhaustive_named,
    non_exhaustive_twin_block, non_exhaustive_unnamed,
};
