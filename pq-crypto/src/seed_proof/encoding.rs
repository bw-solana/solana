//! Reject adversarial collection dimensions before serde allocates their Vecs.
//! Every sequence, tuple and nested element shares one global decoding budget.
use {
    serde::{
        Deserialize, Deserializer,
        de::{self, DeserializeSeed, SeqAccess, Visitor},
    },
    std::{cell::Cell, fmt},
};

const MAX_SEQUENCE: usize = 4096;
const MAX_ELEMENTS: usize = 8 * 1024 * 1024;

struct Limited<'a, D> {
    inner: D,
    remaining: &'a Cell<usize>,
}
struct LimitedVisitor<'a, V> {
    inner: V,
    remaining: &'a Cell<usize>,
}
struct LimitedSeq<'a, A> {
    inner: A,
    remaining: &'a Cell<usize>,
}
struct LimitedSeed<'a, S> {
    inner: S,
    remaining: &'a Cell<usize>,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for LimitedSeed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Limited {
            inner,
            remaining: self.remaining,
        })
    }
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for LimitedSeq<'_, A> {
    type Error = A::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        let remaining = self.remaining.get();
        if remaining == 0 {
            return Err(de::Error::custom(
                "seed proof decode element budget exhausted",
            ));
        }
        self.remaining.set(remaining - 1);
        self.inner.next_element_seed(LimitedSeed {
            inner: seed,
            remaining: self.remaining,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

macro_rules! visit_primitive {
    ($($method:ident($ty:ty)),* $(,)?) => {$ (
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> { self.inner.$method(value) }
    )*};
}

impl<'de, V: Visitor<'de>> Visitor<'de> for LimitedVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.inner.expecting(formatter)
    }
    visit_primitive!(
        visit_bool(bool),
        visit_i8(i8),
        visit_i16(i16),
        visit_i32(i32),
        visit_i64(i64),
        visit_i128(i128),
        visit_u8(u8),
        visit_u16(u16),
        visit_u32(u32),
        visit_u64(u64),
        visit_u128(u128),
        visit_f32(f32),
        visit_f64(f64),
        visit_char(char)
    );
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.inner.visit_str(value)
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.inner.visit_borrowed_str(value)
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.inner.visit_string(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        self.inner.visit_bytes(value)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.inner.visit_borrowed_bytes(value)
    }
    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.inner.visit_byte_buf(value)
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_some<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Limited {
            inner,
            remaining: self.remaining,
        })
    }
    fn visit_newtype_struct<D: Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Limited {
            inner,
            remaining: self.remaining,
        })
    }
    fn visit_seq<A: SeqAccess<'de>>(self, sequence: A) -> Result<Self::Value, A::Error> {
        if sequence
            .size_hint()
            .is_some_and(|length| length > MAX_SEQUENCE || length > self.remaining.get())
        {
            return Err(de::Error::custom(
                "seed proof sequence dimension exceeds fixed bound",
            ));
        }
        self.inner.visit_seq(LimitedSeq {
            inner: sequence,
            remaining: self.remaining,
        })
    }
    // The fixed proof has no enums or maps. Reject these shapes instead of
    // delegating a recursive allocation path not covered by our sequence bound.
    fn visit_map<A: de::MapAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(de::Error::custom("maps are not in the seed proof encoding"))
    }
    fn visit_enum<A: de::EnumAccess<'de>>(self, _: A) -> Result<Self::Value, A::Error> {
        Err(de::Error::custom(
            "enums are not in the seed proof encoding",
        ))
    }
}

macro_rules! deserialize_primitive {
    ($($method:ident),* $(,)?) => {$ (
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> { self.inner.$method(visitor) }
    )*};
}

macro_rules! deserialize_visitor {
    ($($method:ident),* $(,)?) => {$ (
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> { self.inner.$method(LimitedVisitor { inner: visitor, remaining: self.remaining }) }
    )*};
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Limited<'_, D> {
    type Error = D::Error;
    deserialize_primitive!(
        deserialize_any,
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_i128,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_u128,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier,
        deserialize_ignored_any
    );
    deserialize_visitor!(deserialize_option, deserialize_seq, deserialize_map);
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_unit_struct(name, visitor)
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_newtype_struct(
            name,
            LimitedVisitor {
                inner: visitor,
                remaining: self.remaining,
            },
        )
    }
    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple(
            length,
            LimitedVisitor {
                inner: visitor,
                remaining: self.remaining,
            },
        )
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple_struct(
            name,
            length,
            LimitedVisitor {
                inner: visitor,
                remaining: self.remaining,
            },
        )
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_struct(
            name,
            fields,
            LimitedVisitor {
                inner: visitor,
                remaining: self.remaining,
            },
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_enum(
            name,
            variants,
            LimitedVisitor {
                inner: visitor,
                remaining: self.remaining,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

pub(super) fn decode<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<(T, &'de [u8]), postcard::Error> {
    let remaining = Cell::new(MAX_ELEMENTS);
    let mut deserializer = postcard::Deserializer::from_bytes(bytes);
    let value = T::deserialize(Limited {
        inner: &mut deserializer,
        remaining: &remaining,
    })?;
    Ok((value, deserializer.finalize()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dimensions_are_rejected_before_sequence_allocation_including_nested() {
        let large = postcard::to_allocvec(&vec![0_u8; MAX_SEQUENCE + 1]).unwrap();
        assert!(decode::<Vec<u8>>(&large).is_err());
        let large = postcard::to_allocvec(&vec![vec![0_u8; MAX_SEQUENCE + 1]]).unwrap();
        assert!(decode::<Vec<Vec<u8>>>(&large).is_err());
        let valid = postcard::to_allocvec(&vec![vec![1_u8, 2, 3]]).unwrap();
        assert_eq!(
            decode::<Vec<Vec<u8>>>(&valid).unwrap().0,
            vec![vec![1, 2, 3]]
        );
        let huge_length_only = [0xff, 0xff, 0xff, 0xff, 0x0f];
        assert!(decode::<Vec<Vec<u8>>>(&huge_length_only).is_err());
    }
}
