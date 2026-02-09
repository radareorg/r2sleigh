use r2ssa::SSAVar;

use crate::model::{StructShape, Type, TypeId};
use crate::solver::SolvedTypes;

pub trait TypeOracle {
    fn type_of(&self, var: &SSAVar) -> TypeId;
    fn struct_shape(&self, ty: TypeId) -> Option<&StructShape>;
    fn is_pointer(&self, ty: TypeId) -> bool;
    fn is_array(&self, ty: TypeId) -> bool;
    fn field_name(&self, ty: TypeId, offset: u64) -> Option<&str>;
    fn field_name_any(&self, offset: u64) -> Option<&str>;
}

impl TypeOracle for SolvedTypes {
    fn type_of(&self, var: &SSAVar) -> TypeId {
        self.var_types.get(var).copied().unwrap_or(self.top_id)
    }

    fn struct_shape(&self, ty: TypeId) -> Option<&StructShape> {
        match self.arena.get(ty) {
            Type::Struct(shape) => Some(shape),
            Type::Ptr(inner) => match self.arena.get(*inner) {
                Type::Struct(shape) => Some(shape),
                _ => None,
            },
            _ => None,
        }
    }

    fn is_pointer(&self, ty: TypeId) -> bool {
        matches!(self.arena.get(ty), Type::Ptr(_))
    }

    fn is_array(&self, ty: TypeId) -> bool {
        matches!(self.arena.get(ty), Type::Array { .. })
    }

    fn field_name(&self, ty: TypeId, offset: u64) -> Option<&str> {
        self.struct_shape(ty)
            .and_then(|shape| shape.fields.get(&offset))
            .and_then(|field| field.name.as_deref())
    }

    fn field_name_any(&self, offset: u64) -> Option<&str> {
        let mut matched: Option<&str> = None;
        for (_, ty) in self.arena.iter() {
            let Type::Struct(shape) = ty else {
                continue;
            };
            let Some(name) = shape
                .fields
                .get(&offset)
                .and_then(|field| field.name.as_deref())
            else {
                continue;
            };
            match matched {
                None => matched = Some(name),
                Some(existing) if existing == name => {}
                Some(_) => return None,
            }
        }
        matched
    }
}
