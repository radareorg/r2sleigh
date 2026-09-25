//! The Sleigh user operations this lift gives their exact meaning, resolved
//! once per specification.
//!
//! A `CallOther` names an operation only by an index the compiled
//! specification assigns, so the index is resolved against the specification's
//! own operation table when the specification is loaded, and every `CallOther`
//! after that is one vector lookup. The table below is the single statement of
//! which operations are modelled on their own, one `CallOther` at a time: each
//! row is an exact name the specification declares, never a prefix or a
//! pattern, so a name this lift does not know is simply absent and its
//! `CallOther` keeps refusing. The AArch64 exclusive-access pair is not here:
//! it means something only together with the load or store beside it, and
//! `internal_control` recognises it as that idiom.

use std::collections::HashMap;

/// A user operation whose meaning is exactly expressible in the ordinary
/// vocabulary, and which the lift therefore expands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModelledUserOperation {
    /// AArch64 `EXT`.
    NeonExt,
    /// AArch64 `USHL`.
    NeonUshl,
    /// AArch64 `REV64`.
    NeonRev64,
    /// AArch64 `UMAX` (`max`) and `UMIN`.
    NeonMinMax { max: bool },
    /// AArch64 `UMAXV` (`max`) and `UMINV`.
    NeonMinMaxAcross { max: bool },
    /// AArch64 `TBL` and `TBX` with one table register.
    A64Tbl,
    /// A trap: control leaves for an exception handler and does not come back.
    Trap,
    /// ARM `bx` switching instruction set, which the p-code has already done.
    SetIsaMode,
    /// x86 `PMOVSX*` / `PMOVZX*`.
    PackedExtension(PackedExtension),
}

/// One x86 packed sign or zero extension: every element of `from_bytes` in
/// the source's low part becomes an element of `to_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PackedExtension {
    pub(crate) from_bytes: u32,
    pub(crate) to_bytes: u32,
    pub(crate) extension: Extension,
    pub(crate) form: EncodingForm,
}

/// How each element is widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Extension {
    Sign,
    Zero,
}

/// The encoding a packed-extension operation name belongs to, which fixes the
/// operands the specification passes it and the width of what it produces.
///
/// The shapes are read from the specification itself (Ghidra's `ia.sinc`,
/// `avx.sinc`, `avx2.sinc` and `avx512.sinc`):
///
/// * `Legacy` -- SSE4.1, `XmmReg = pmovsxbd(XmmReg, src)`: the old destination
///   is passed as the first operand and the result is the 16-byte register.
/// * `Vex128` -- `local tmp:16 = vpmovsxbd_avx(src)`.
/// * `Vex256` -- `local tmp:32 = vpmovsxbd_avx2(src)`.
/// * `EvexVl` -- the AVX512VL forms, `XmmResult` or `YmmResult`: 16 or 32 bytes.
/// * `Evex512` -- the AVX512F and AVX512BW forms, `ZmmResult`: 64 bytes.
///
/// What happens to the bits above the written result -- the XMM sub-register
/// write of the legacy form, `ZmmReg1 = zext(tmp)` of VEX, the opmask merge of
/// EVEX -- is the specification's own p-code around the operation, and stays
/// exactly as the specification writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodingForm {
    Legacy,
    Vex128,
    Vex256,
    EvexVl,
    Evex512,
}

impl EncodingForm {
    /// Whether a result of `bytes` is one this encoding produces.
    pub(crate) const fn produces(self, bytes: u32) -> bool {
        match self {
            Self::Legacy | Self::Vex128 => bytes == 16,
            Self::Vex256 => bytes == 32,
            Self::EvexVl => bytes == 16 || bytes == 32,
            Self::Evex512 => bytes == 64,
        }
    }

    /// Whether the specification passes the old destination ahead of the
    /// source. Only the legacy form does, and the architecture reads none of
    /// it: every bit of the written register is defined from the source.
    pub(crate) const fn passes_old_destination(self) -> bool {
        matches!(self, Self::Legacy)
    }
}

/// One packed-extension operation, spelled in each encoding the
/// specification declares, in the order of [`PACKED_FORMS`].
struct PackedExtensionRow {
    from_bytes: u32,
    to_bytes: u32,
    extension: Extension,
    names: [&'static str; PACKED_FORMS.len()],
}

/// The encodings a packed-extension row names, in the order its names are listed.
const PACKED_FORMS: [EncodingForm; 5] = [
    EncodingForm::Legacy,
    EncodingForm::Vex128,
    EncodingForm::Vex256,
    EncodingForm::EvexVl,
    EncodingForm::Evex512,
];

/// Intel SDM `PMOVSX` and `PMOVZX`: `bw`, `bd`, `bq`, `wd`, `wq`, `dq`, each in
/// the five encodings. The byte-to-word forms are AVX512BW at 512 bits; the
/// others are AVX512F.
const PACKED_EXTENSIONS: [PackedExtensionRow; 12] = [
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 2,
        extension: Extension::Sign,
        names: [
            "pmovsxbw",
            "vpmovsxbw_avx",
            "vpmovsxbw_avx2",
            "vpmovsxbw_avx512vl",
            "vpmovsxbw_avx512bw",
        ],
    },
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 4,
        extension: Extension::Sign,
        names: [
            "pmovsxbd",
            "vpmovsxbd_avx",
            "vpmovsxbd_avx2",
            "vpmovsxbd_avx512vl",
            "vpmovsxbd_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 8,
        extension: Extension::Sign,
        names: [
            "pmovsxbq",
            "vpmovsxbq_avx",
            "vpmovsxbq_avx2",
            "vpmovsxbq_avx512vl",
            "vpmovsxbq_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 2,
        to_bytes: 4,
        extension: Extension::Sign,
        names: [
            "pmovsxwd",
            "vpmovsxwd_avx",
            "vpmovsxwd_avx2",
            "vpmovsxwd_avx512vl",
            "vpmovsxwd_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 2,
        to_bytes: 8,
        extension: Extension::Sign,
        names: [
            "pmovsxwq",
            "vpmovsxwq_avx",
            "vpmovsxwq_avx2",
            "vpmovsxwq_avx512vl",
            "vpmovsxwq_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 4,
        to_bytes: 8,
        extension: Extension::Sign,
        names: [
            "pmovsxdq",
            "vpmovsxdq_avx",
            "vpmovsxdq_avx2",
            "vpmovsxdq_avx512vl",
            "vpmovsxdq_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 2,
        extension: Extension::Zero,
        names: [
            "pmovzxbw",
            "vpmovzxbw_avx",
            "vpmovzxbw_avx2",
            "vpmovzxbw_avx512vl",
            "vpmovzxbw_avx512bw",
        ],
    },
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 4,
        extension: Extension::Zero,
        names: [
            "pmovzxbd",
            "vpmovzxbd_avx",
            "vpmovzxbd_avx2",
            "vpmovzxbd_avx512vl",
            "vpmovzxbd_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 1,
        to_bytes: 8,
        extension: Extension::Zero,
        names: [
            "pmovzxbq",
            "vpmovzxbq_avx",
            "vpmovzxbq_avx2",
            "vpmovzxbq_avx512vl",
            "vpmovzxbq_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 2,
        to_bytes: 4,
        extension: Extension::Zero,
        names: [
            "pmovzxwd",
            "vpmovzxwd_avx",
            "vpmovzxwd_avx2",
            "vpmovzxwd_avx512vl",
            "vpmovzxwd_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 2,
        to_bytes: 8,
        extension: Extension::Zero,
        names: [
            "pmovzxwq",
            "vpmovzxwq_avx",
            "vpmovzxwq_avx2",
            "vpmovzxwq_avx512vl",
            "vpmovzxwq_avx512f",
        ],
    },
    PackedExtensionRow {
        from_bytes: 4,
        to_bytes: 8,
        extension: Extension::Zero,
        names: [
            "pmovzxdq",
            "vpmovzxdq_avx",
            "vpmovzxdq_avx2",
            "vpmovzxdq_avx512vl",
            "vpmovzxdq_avx512f",
        ],
    },
];

/// The operations outside the packed-extension family, by the exact name the
/// specification declares.
const NAMED: [(&str, ModelledUserOperation); 11] = [
    ("NEON_ext", ModelledUserOperation::NeonExt),
    ("NEON_ushl", ModelledUserOperation::NeonUshl),
    ("NEON_rev64", ModelledUserOperation::NeonRev64),
    ("NEON_umax", ModelledUserOperation::NeonMinMax { max: true }),
    (
        "NEON_umin",
        ModelledUserOperation::NeonMinMax { max: false },
    ),
    (
        "NEON_umaxv",
        ModelledUserOperation::NeonMinMaxAcross { max: true },
    ),
    (
        "NEON_uminv",
        ModelledUserOperation::NeonMinMaxAcross { max: false },
    ),
    ("a64_TBL", ModelledUserOperation::A64Tbl),
    ("SoftwareBreakpoint", ModelledUserOperation::Trap),
    ("UndefinedInstructionException", ModelledUserOperation::Trap),
    ("setISAMode", ModelledUserOperation::SetIsaMode),
];

/// Every modelled operation with the exact name it is declared under.
pub(crate) fn modelled_user_operations()
-> impl Iterator<Item = (&'static str, ModelledUserOperation)> {
    let packed = PACKED_EXTENSIONS.iter().flat_map(|row| {
        row.names.iter().zip(PACKED_FORMS).map(move |(name, form)| {
            (
                *name,
                ModelledUserOperation::PackedExtension(PackedExtension {
                    from_bytes: row.from_bytes,
                    to_bytes: row.to_bytes,
                    extension: row.extension,
                    form,
                }),
            )
        })
    });
    NAMED.into_iter().chain(packed)
}

/// The modelled operation at each index of a specification's user-operation
/// table, `None` where the operation is not one this lift models.
///
/// Resolved once per loaded specification: the table has a few dozen rows and
/// the specification a few thousand operations, so this is one hash lookup per
/// declared operation, and every `CallOther` afterwards is one vector index.
pub(crate) fn resolve_modelled_user_operations(
    user_ops: &[String],
) -> Vec<Option<ModelledUserOperation>> {
    let table: HashMap<&str, ModelledUserOperation> = modelled_user_operations().collect();
    user_ops
        .iter()
        .map(|name| table.get(name.as_str()).copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No name is claimed by two rows, so what an index resolves to is not
    /// decided by the order the table happens to be written in.
    #[test]
    fn every_modelled_name_is_claimed_once() {
        let mut seen = std::collections::BTreeSet::new();
        for (name, _) in modelled_user_operations() {
            assert!(seen.insert(name), "{name} is claimed twice");
        }
        assert_eq!(seen.len(), NAMED.len() + 12 * PACKED_FORMS.len());
    }

    /// An index resolves by the specification's exact name, and a name that
    /// is not in the table -- including one sharing a modelled name's prefix
    /// -- resolves to nothing.
    #[test]
    fn resolution_is_by_exact_name() {
        let declared = [
            "pmovsxbd".to_string(),
            "pmovsxbd_extra".to_string(),
            "vpmovzxwq_avx2".to_string(),
            "pshufb".to_string(),
        ];
        let resolved = resolve_modelled_user_operations(&declared);
        assert_eq!(
            resolved,
            vec![
                Some(ModelledUserOperation::PackedExtension(PackedExtension {
                    from_bytes: 1,
                    to_bytes: 4,
                    extension: Extension::Sign,
                    form: EncodingForm::Legacy,
                })),
                None,
                Some(ModelledUserOperation::PackedExtension(PackedExtension {
                    from_bytes: 2,
                    to_bytes: 8,
                    extension: Extension::Zero,
                    form: EncodingForm::Vex256,
                })),
                None,
            ]
        );
    }
}
