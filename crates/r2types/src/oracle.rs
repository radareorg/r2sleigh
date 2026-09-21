use r2ssa::SSAVar;

use crate::facts::ResolvedFieldLayout;
use crate::model::{StructShape, TypeId};

pub trait TypeOracle {
    fn type_of(&self, var: &SSAVar) -> TypeId;
    fn struct_shape(&self, ty: TypeId) -> Option<&StructShape>;
    fn is_pointer(&self, ty: TypeId) -> bool;
    fn is_array(&self, ty: TypeId) -> bool;
    fn field_name(&self, ty: TypeId, offset: u64) -> Option<&str>;
    fn field_name_any(&self, offset: u64) -> Option<&str>;

    fn field_layout(&self, ty: TypeId, offset: u64) -> Option<ResolvedFieldLayout> {
        self.field_name(ty, offset)
            .map(|name| ResolvedFieldLayout::direct(None, offset, name))
    }

    fn indexed_field_layout(
        &self,
        ty: TypeId,
        elem_stride: u64,
        field_offset: u64,
    ) -> Option<ResolvedFieldLayout> {
        let combined_offset = elem_stride.checked_add(field_offset)?;
        self.field_layout(ty, combined_offset).map(|layout| {
            ResolvedFieldLayout::indexed(
                layout.owner_name,
                elem_stride,
                field_offset,
                layout.field_name,
            )
        })
    }
}
