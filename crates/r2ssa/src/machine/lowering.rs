//! One machine expression per operation the body performs.

use super::*;

impl MachineBuilder {
    pub(crate) fn lower_outputless_inst(
        &mut self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
    ) -> Result<(), MachineBuildError> {
        let graph = artifact.graph();
        for (input_idx, input) in inst.inputs.iter().copied().enumerate() {
            let graph_value = graph
                .value(input)
                .ok_or(MachineBuildError::MissingGraphValue(input))?;
            if graph_value.var.constant_bits().is_some() {
                self.intern_value(graph_value)?;
            }
            self.record_whole_use(graph, inst, input_idx)?;
        }
        if let InstPayload::Op(
            op
            @ (SSAOp::Store { .. } | SSAOp::StoreConditional { .. } | SSAOp::StoreGuarded { .. }),
        ) = &inst.payload
        {
            self.intern_store_address(artifact, inst, op)?;
        }
        Ok(())
    }

    pub(crate) fn lower_inst(
        &mut self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
        producer: CanonicalInstructionId,
        output: MachineValueBinding,
    ) -> Result<MachineExprId, MachineBuildError> {
        let graph = artifact.graph();
        let output_unsigned = integer_type(output.width_bits, MachineSignedness::Unsigned);
        let (ty, kind) = match &inst.payload {
            InstPayload::Phi { .. } => {
                if inst.inputs.is_empty() {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 1,
                        actual: 0,
                    });
                }
                let mut inputs = Vec::with_capacity(inst.inputs.len());
                for (input_idx, value) in inst.inputs.iter().enumerate() {
                    inputs.push(
                        self.intern_value(
                            graph
                                .value(*value)
                                .ok_or(MachineBuildError::MissingGraphValue(*value))?,
                        )?,
                    );
                    self.record_whole_use(graph, inst, input_idx)?;
                }
                (
                    output_unsigned,
                    MachineExprKind::Phi {
                        inputs: inputs.into_boxed_slice(),
                    },
                )
            }
            InstPayload::Op(op) => self.lower_op(artifact, inst, op, output)?,
        };
        Ok(self.push(ty, Some(producer), kind))
    }

    pub(crate) fn lower_op(
        &mut self,
        artifact: &SsaArtifact,
        inst: &GraphInst,
        op: &SSAOp,
        output: MachineValueBinding,
    ) -> Result<(MachineType, MachineExprKind), MachineBuildError> {
        let graph = artifact.graph();
        let unsigned = integer_type(output.width_bits, MachineSignedness::Unsigned);
        let signed = integer_type(output.width_bits, MachineSignedness::Signed);
        match op {
            // What a conditional store answers is its own notion: the store
            // it names, through the address it names, and whether anything
            // took the monitor away in between. The operands are stated and
            // the outcome is not derived from them, which is exactly true of
            // the machine.
            SSAOp::StoreConditional { .. } => {
                let mut operands = Vec::with_capacity(2);
                for (input_idx, input) in inst.inputs.iter().enumerate() {
                    let value = graph
                        .value(*input)
                        .ok_or(MachineBuildError::MissingGraphValue(*input))?;
                    operands.push(self.intern_value(value)?);
                    self.record_whole_use(graph, inst, input_idx)?;
                }
                let [address, value] = operands.as_slice() else {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 2,
                        actual: operands.len(),
                    });
                };
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::ExclusiveStoreSucceeded {
                        address: *address,
                        value: *value,
                    },
                ))
            }
            // A linked load reads what a plain one reads: the linkage it sets
            // is an effect of the instruction, not a property of the value.
            // A guarded one reads the same, under its condition.
            SSAOp::Load { .. } | SSAOp::LoadLinked { .. } | SSAOp::LoadGuarded { .. } => {
                let accesses = artifact
                    .facts()
                    .structured
                    .memory_accesses
                    .values()
                    .filter(|access| access.id.inst == inst.id)
                    .collect::<Vec<_>>();
                let [access] = accesses.as_slice() else {
                    return Err(MachineBuildError::UnsupportedOperation {
                        inst: inst.id,
                        op: Box::new(op.clone()),
                    });
                };
                let width_bits = access.width.checked_mul(8).unwrap_or(0);
                let source_space = artifact
                    .machine_context()
                    .memory_space_at(access.block_addr, access.op_index);
                let model = artifact.machine_context().memory_model();
                let space_model = source_space.and_then(|space| model.space(space));
                let prepared_op = artifact
                    .function()
                    .get_block(access.block_addr)
                    .and_then(|block| block.ops.get(access.op_index));
                if !access.provenance_complete
                    || access.is_write
                    || access.id.ordinal != 0
                    || access.value != Some(output.value)
                    || prepared_op.is_none_or(|prepared_op| {
                        source_space.is_none_or(|source_space| {
                            !memory_access_authorities_match(
                                graph,
                                artifact.objects(),
                                op,
                                prepared_op,
                                source_space,
                                access,
                                artifact
                                    .facts()
                                    .structured
                                    .member_run_stores
                                    .get(&access.id.inst),
                            )
                        })
                    })
                    // A guarded read states its condition beside the
                    // address; every other read names the address alone.
                    || !read_operands_are_exact(Some(op), &inst.inputs, access.address)
                    || width_bits == 0
                    || width_bits != output.width_bits
                    || !model.is_available()
                    || !model.is_coherent()
                    || space_model.is_none()
                {
                    return Err(MachineBuildError::UnsupportedOperation {
                        inst: inst.id,
                        op: Box::new(op.clone()),
                    });
                }
                let space_model = space_model.expect("checked memory space");
                let address = graph
                    .value(access.address)
                    .ok_or(MachineBuildError::MissingGraphValue(access.address))?;
                let space = MachineAddressSpace::from(space_model.space());
                let address = self.intern_address(
                    artifact,
                    address,
                    access.object,
                    space,
                    space_model.address_bits(),
                )?;
                self.record_whole_use(graph, inst, 0)?;
                let Some(guard) = inst.inputs.get(1).copied() else {
                    return Ok((
                        unsigned,
                        MachineExprKind::MemoryRead {
                            access: access.id,
                            object: access.object,
                            space,
                            endianness: space_model.endianness(),
                            word_size_bytes: space_model.word_size_bytes(),
                            address,
                            width_bits,
                        },
                    ));
                };
                let guard_value = graph
                    .value(guard)
                    .ok_or(MachineBuildError::MissingGraphValue(guard))?;
                let binding = binding_for_value(guard_value)?;
                let guard = self.intern_value_with_type(
                    guard_value,
                    MachineType::Bool {
                        storage_bits: binding.width_bits,
                    },
                )?;
                self.record_whole_use(graph, inst, 1)?;
                Ok((
                    unsigned,
                    MachineExprKind::GuardedRead {
                        access: access.id,
                        object: access.object,
                        space,
                        endianness: space_model.endianness(),
                        word_size_bytes: space_model.word_size_bytes(),
                        address,
                        guard,
                        width_bits,
                    },
                ))
            }
            // A restore hands back the value it was given, so as an
            // expression it is a copy. What it says beyond that -- that the
            // value came back across a call boundary rather than from an
            // instruction this function executed -- is carried by the
            // operation's own kind, and read by the accounting rather than by
            // the expression.
            SSAOp::Copy { .. } | SSAOp::CallRestore { .. } => {
                let inputs = self.operand_nodes(graph, inst, 1)?;
                Ok((unsigned, MachineExprKind::Copy { input: inputs[0] }))
            }
            SSAOp::IntAdd { .. } | SSAOp::IntSub { .. } | SSAOp::IntMult { .. } => {
                let inputs = self.operand_nodes(graph, inst, 2)?;
                let op = match op {
                    SSAOp::IntAdd { .. } => MachineArithmeticOp::Add,
                    SSAOp::IntSub { .. } => MachineArithmeticOp::Subtract,
                    SSAOp::IntMult { .. } => MachineArithmeticOp::Multiply,
                    _ => unreachable!(),
                };
                Ok((
                    unsigned,
                    MachineExprKind::Arithmetic {
                        op,
                        mode: MachineArithmeticMode::Wrapping,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::IntDiv { .. } | SSAOp::IntSDiv { .. } => {
                let inputs = self.exact_width_operand_nodes(graph, inst, 2, output.width_bits)?;
                let (interpretation, ty) = match op {
                    SSAOp::IntDiv { .. } => (MachineSignedness::Unsigned, unsigned),
                    _ => (MachineSignedness::Signed, signed),
                };
                Ok((
                    ty,
                    MachineExprKind::Divide {
                        interpretation,
                        zero_divisor: MachineZeroDivisorBehavior::Undefined,
                        dividend: inputs[0],
                        divisor: inputs[1],
                    },
                ))
            }
            SSAOp::IntRem { .. } | SSAOp::IntSRem { .. } => {
                let inputs = self.exact_width_operand_nodes(graph, inst, 2, output.width_bits)?;
                let (interpretation, ty) = match op {
                    SSAOp::IntRem { .. } => (MachineSignedness::Unsigned, unsigned),
                    _ => (MachineSignedness::Signed, signed),
                };
                Ok((
                    ty,
                    MachineExprKind::Remainder {
                        interpretation,
                        zero_divisor: MachineZeroDivisorBehavior::Undefined,
                        dividend: inputs[0],
                        divisor: inputs[1],
                    },
                ))
            }
            SSAOp::IntNegate { .. } => {
                let inputs = self.exact_width_operand_nodes(graph, inst, 1, output.width_bits)?;
                Ok((
                    unsigned,
                    MachineExprKind::Negate {
                        mode: MachineArithmeticMode::Wrapping,
                        input: inputs[0],
                    },
                ))
            }
            SSAOp::PopCount { .. } => {
                if inst.inputs.len() != 1 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 1,
                        actual: inst.inputs.len(),
                    });
                }
                let input_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let input_bits = binding_for_value(input_value)?.width_bits;
                let required_output_bits = u32::BITS - input_bits.leading_zeros();
                if input_bits == 0 || output.width_bits < required_output_bits {
                    return Err(MachineBuildError::WidthMismatch {
                        inst: inst.id,
                        expected_bits: required_output_bits,
                        actual_bits: output.width_bits,
                    });
                }
                let input = self.intern_value(input_value)?;
                self.record_whole_use(graph, inst, 0)?;
                Ok((unsigned, MachineExprKind::PopulationCount { input }))
            }
            SSAOp::IntCarry { .. } | SSAOp::IntSCarry { .. } | SSAOp::IntSBorrow { .. } => {
                let inputs = self.operand_nodes(graph, inst, 2)?;
                let op = match op {
                    SSAOp::IntCarry { .. } => MachineArithmeticFlagOp::UnsignedCarry,
                    SSAOp::IntSCarry { .. } => MachineArithmeticFlagOp::SignedCarry,
                    SSAOp::IntSBorrow { .. } => MachineArithmeticFlagOp::SignedBorrow,
                    _ => unreachable!(),
                };
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::ArithmeticFlag {
                        op,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::IntAnd { .. } | SSAOp::IntOr { .. } | SSAOp::IntXor { .. } => {
                // Sleigh may write the low part of a wider bitwise operation
                // directly into a narrower varnode. Make that truncation
                // explicit in the typed machine expression instead of
                // accepting mismatched child widths.
                let inputs = self.narrowed_operand_nodes(graph, inst, 2, output.width_bits)?;
                let op = match op {
                    SSAOp::IntAnd { .. } => MachineBitwiseOp::And,
                    SSAOp::IntOr { .. } => MachineBitwiseOp::Or,
                    SSAOp::IntXor { .. } => MachineBitwiseOp::Xor,
                    _ => unreachable!(),
                };
                Ok((
                    unsigned,
                    MachineExprKind::Bitwise {
                        op,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::IntNot { .. } => {
                let inputs = self.operand_nodes(graph, inst, 1)?;
                Ok((unsigned, MachineExprKind::BitwiseNot { input: inputs[0] }))
            }
            SSAOp::BoolNot { .. } => {
                if inst.inputs.len() != 1 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 1,
                        actual: inst.inputs.len(),
                    });
                }
                let input_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let input = self.intern_boolean_value(graph, input_value, inst.id)?;
                self.record_whole_use(graph, inst, 0)?;
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::BooleanNot { input },
                ))
            }
            SSAOp::BoolAnd { .. } | SSAOp::BoolOr { .. } | SSAOp::BoolXor { .. } => {
                if inst.inputs.len() != 2 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 2,
                        actual: inst.inputs.len(),
                    });
                }
                let left_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let right_value = graph
                    .value(inst.inputs[1])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[1]))?;
                let left = self.intern_boolean_value(graph, left_value, inst.id)?;
                let right = self.intern_boolean_value(graph, right_value, inst.id)?;
                self.record_whole_use(graph, inst, 0)?;
                self.record_whole_use(graph, inst, 1)?;
                let op = match op {
                    SSAOp::BoolAnd { .. } => MachineBooleanOp::And,
                    SSAOp::BoolOr { .. } => MachineBooleanOp::Or,
                    SSAOp::BoolXor { .. } => MachineBooleanOp::Xor,
                    _ => unreachable!(),
                };
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::Boolean { op, left, right },
                ))
            }
            SSAOp::IntLeft { .. } | SSAOp::IntRight { .. } | SSAOp::IntSRight { .. } => {
                if inst.inputs.len() != 2 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 2,
                        actual: inst.inputs.len(),
                    });
                }
                // A shift does not prove a projection from a wider carrier.
                // Canonical R2IL requires the value and destination widths to
                // match; reject malformed input locally instead of inventing
                // an Extract. The count is independent and stays whole at its
                // source width.
                let value = self.exact_width_operand_node(graph, inst, 0, output.width_bits)?;
                let count_value = graph
                    .value(inst.inputs[1])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[1]))?;
                let count = self.intern_value(count_value)?;
                self.record_whole_use(graph, inst, 1)?;
                let (kind, overshift, ty) = match op {
                    SSAOp::IntLeft { .. } => (
                        MachineShiftKind::Left,
                        MachineOvershiftBehavior::Zero,
                        unsigned,
                    ),
                    SSAOp::IntRight { .. } => (
                        MachineShiftKind::LogicalRight,
                        MachineOvershiftBehavior::Zero,
                        unsigned,
                    ),
                    SSAOp::IntSRight { .. } => (
                        MachineShiftKind::ArithmeticRight,
                        MachineOvershiftBehavior::SignFill,
                        signed,
                    ),
                    _ => unreachable!(),
                };
                Ok((
                    ty,
                    MachineExprKind::Shift {
                        kind,
                        overshift,
                        value,
                        count,
                    },
                ))
            }
            SSAOp::IntEqual { .. }
            | SSAOp::IntNotEqual { .. }
            | SSAOp::IntLess { .. }
            | SSAOp::IntSLess { .. }
            | SSAOp::IntLessEqual { .. }
            | SSAOp::IntSLessEqual { .. } => {
                let inputs = self.operand_nodes(graph, inst, 2)?;
                let (op, interpretation) = match op {
                    SSAOp::IntEqual { .. } => {
                        (MachineComparisonOp::Equal, MachineSignedness::Unsigned)
                    }
                    SSAOp::IntNotEqual { .. } => {
                        (MachineComparisonOp::NotEqual, MachineSignedness::Unsigned)
                    }
                    SSAOp::IntLess { .. } => {
                        (MachineComparisonOp::LessThan, MachineSignedness::Unsigned)
                    }
                    SSAOp::IntSLess { .. } => {
                        (MachineComparisonOp::LessThan, MachineSignedness::Signed)
                    }
                    SSAOp::IntLessEqual { .. } => (
                        MachineComparisonOp::LessThanOrEqual,
                        MachineSignedness::Unsigned,
                    ),
                    SSAOp::IntSLessEqual { .. } => (
                        MachineComparisonOp::LessThanOrEqual,
                        MachineSignedness::Signed,
                    ),
                    _ => unreachable!(),
                };
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::Compare {
                        op,
                        interpretation,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::FloatAdd { .. }
            | SSAOp::FloatSub { .. }
            | SSAOp::FloatMult { .. }
            | SSAOp::FloatDiv { .. } => {
                let float = self.float_type(inst, output.width_bits)?;
                let inputs = self.float_operand_nodes(graph, inst, 2, output.width_bits)?;
                let op = match op {
                    SSAOp::FloatAdd { .. } => MachineFloatOp::Add,
                    SSAOp::FloatSub { .. } => MachineFloatOp::Subtract,
                    SSAOp::FloatMult { .. } => MachineFloatOp::Multiply,
                    _ => MachineFloatOp::Divide,
                };
                Ok((
                    float,
                    MachineExprKind::FloatArithmetic {
                        op,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::FloatNeg { .. }
            | SSAOp::FloatAbs { .. }
            | SSAOp::FloatSqrt { .. }
            | SSAOp::FloatCeil { .. }
            | SSAOp::FloatFloor { .. }
            | SSAOp::FloatRound { .. } => {
                let float = self.float_type(inst, output.width_bits)?;
                let inputs = self.float_operand_nodes(graph, inst, 1, output.width_bits)?;
                let op = match op {
                    SSAOp::FloatNeg { .. } => MachineFloatUnaryOp::Negate,
                    SSAOp::FloatAbs { .. } => MachineFloatUnaryOp::Absolute,
                    SSAOp::FloatSqrt { .. } => MachineFloatUnaryOp::SquareRoot,
                    SSAOp::FloatCeil { .. } => MachineFloatUnaryOp::Ceiling,
                    SSAOp::FloatFloor { .. } => MachineFloatUnaryOp::Floor,
                    _ => MachineFloatUnaryOp::Round,
                };
                Ok((
                    float,
                    MachineExprKind::FloatUnary {
                        op,
                        input: inputs[0],
                    },
                ))
            }
            SSAOp::FloatNaN { .. } => {
                let width = self.operand_width(graph, inst, 0)?;
                let inputs = self.float_operand_nodes(graph, inst, 1, width)?;
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::FloatUnary {
                        op: MachineFloatUnaryOp::IsNan,
                        input: inputs[0],
                    },
                ))
            }
            SSAOp::FloatEqual { .. }
            | SSAOp::FloatNotEqual { .. }
            | SSAOp::FloatLess { .. }
            | SSAOp::FloatLessEqual { .. } => {
                let width = self.operand_width(graph, inst, 0)?;
                let inputs = self.float_operand_nodes(graph, inst, 2, width)?;
                let op = match op {
                    SSAOp::FloatEqual { .. } => MachineComparisonOp::Equal,
                    SSAOp::FloatNotEqual { .. } => MachineComparisonOp::NotEqual,
                    SSAOp::FloatLess { .. } => MachineComparisonOp::LessThan,
                    _ => MachineComparisonOp::LessThanOrEqual,
                };
                Ok((
                    MachineType::Bool {
                        storage_bits: output.width_bits,
                    },
                    MachineExprKind::FloatCompare {
                        op,
                        left: inputs[0],
                        right: inputs[1],
                    },
                ))
            }
            SSAOp::Int2Float { .. }
            | SSAOp::Float2Int { .. }
            | SSAOp::Trunc { .. }
            | SSAOp::FloatFloat { .. } => {
                let from = self.operand_width(graph, inst, 0)?;
                let (kind, ty, input) = match op {
                    SSAOp::Int2Float { .. } => {
                        let float = self.float_type(inst, output.width_bits)?;
                        let inputs = self.exact_width_operand_nodes(graph, inst, 1, from)?;
                        (MachineCastKind::IntegerToFloat, float, inputs[0])
                    }
                    SSAOp::FloatFloat { .. } => {
                        let float = self.float_type(inst, output.width_bits)?;
                        if from == output.width_bits {
                            return Err(MachineBuildError::InvalidCastWidth {
                                inst: inst.id,
                                kind: MachineCastKind::FloatToFloat,
                                from_bits: from,
                                to_bits: output.width_bits,
                            });
                        }
                        let inputs = self.float_operand_nodes(graph, inst, 1, from)?;
                        (MachineCastKind::FloatToFloat, float, inputs[0])
                    }
                    _ => {
                        let inputs = self.float_operand_nodes(graph, inst, 1, from)?;
                        (MachineCastKind::FloatToInteger, signed, inputs[0])
                    }
                };
                Ok((ty, MachineExprKind::Cast { kind, input }))
            }
            SSAOp::IntZExt { .. } | SSAOp::IntSExt { .. } | SSAOp::Cast { .. } => {
                if inst.inputs.len() != 1 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 1,
                        actual: inst.inputs.len(),
                    });
                }
                let input_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let input = self.intern_value(input_value)?;
                let from = self.nodes[input.index()].ty.width_bits();
                let (kind, ty, valid) = match op {
                    SSAOp::IntZExt { .. } => (
                        MachineCastKind::ZeroExtend,
                        unsigned,
                        output.width_bits > from,
                    ),
                    SSAOp::IntSExt { .. } => (
                        MachineCastKind::SignExtend,
                        signed,
                        output.width_bits > from,
                    ),
                    SSAOp::Cast { .. } => (
                        MachineCastKind::BitReinterpret,
                        unsigned,
                        output.width_bits == from,
                    ),
                    _ => unreachable!(),
                };
                if !valid {
                    return Err(MachineBuildError::InvalidCastWidth {
                        inst: inst.id,
                        kind,
                        from_bits: from,
                        to_bits: output.width_bits,
                    });
                }
                self.record_use(
                    graph,
                    inst,
                    0,
                    MachineUseSlice {
                        bit_offset: 0,
                        width_bits: from,
                        carrier_width_bits: from,
                        conversion: Some(MachineUseConversion {
                            kind,
                            to_width_bits: output.width_bits,
                        }),
                    },
                )?;
                Ok((ty, MachineExprKind::Cast { kind, input }))
            }
            SSAOp::Subpiece { offset, .. } => {
                if inst.inputs.len() != 1 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 1,
                        actual: inst.inputs.len(),
                    });
                }
                let input_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let input = self.intern_value(input_value)?;
                let source_bits = self.nodes[input.index()].ty.width_bits();
                let lsb_bits = offset
                    .checked_mul(8)
                    .ok_or(MachineBuildError::InvalidSubpiece {
                        inst: inst.id,
                        source_bits,
                        result_bits: output.width_bits,
                        lsb_bits: u32::MAX,
                    })?;
                if lsb_bits
                    .checked_add(output.width_bits)
                    .is_none_or(|end| end > source_bits)
                {
                    return Err(MachineBuildError::InvalidSubpiece {
                        inst: inst.id,
                        source_bits,
                        result_bits: output.width_bits,
                        lsb_bits,
                    });
                }
                // The operand is read whole. Where the extraction sits is this
                // operation's own semantics, and the operation renders it;
                // describing it a second time as a property of the read applies
                // the offset twice, and a lane read that shifts twice is zero.
                // It went unseen because a register operand read as itself has
                // its slice replaced with a whole read anyway, so only values
                // composed inside the function -- which have no canonical
                // storage and keep the recorded slice -- ever showed it.
                self.record_use(
                    graph,
                    inst,
                    0,
                    MachineUseSlice {
                        bit_offset: 0,
                        width_bits: source_bits,
                        carrier_width_bits: source_bits,
                        conversion: None,
                    },
                )?;
                Ok((unsigned, MachineExprKind::Extract { input, lsb_bits }))
            }
            SSAOp::Piece { .. } => {
                if inst.inputs.len() != 2 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 2,
                        actual: inst.inputs.len(),
                    });
                }
                let high_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let low_value = graph
                    .value(inst.inputs[1])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[1]))?;
                let high_bits = binding_for_value(high_value)?.width_bits;
                let low_bits = binding_for_value(low_value)?.width_bits;
                let Some(actual_bits) = high_bits.checked_add(low_bits) else {
                    return Err(MachineBuildError::WidthMismatch {
                        inst: inst.id,
                        expected_bits: output.width_bits,
                        actual_bits: u32::MAX,
                    });
                };
                if actual_bits != output.width_bits {
                    return Err(MachineBuildError::WidthMismatch {
                        inst: inst.id,
                        expected_bits: output.width_bits,
                        actual_bits,
                    });
                }
                let high = self.intern_value(high_value)?;
                let low = self.intern_value(low_value)?;
                self.record_whole_use(graph, inst, 0)?;
                self.record_whole_use(graph, inst, 1)?;
                Ok((unsigned, MachineExprKind::Concat { high, low }))
            }
            SSAOp::Insert { .. } => {
                // A lane written into its root (doc/adr-register-identity.md
                // §2): the root read whole, the lane value, and a constant
                // bit position. The projection of the write says the rest.
                if inst.inputs.len() != 3 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 3,
                        actual: inst.inputs.len(),
                    });
                }
                let root_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let lane_value = graph
                    .value(inst.inputs[1])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[1]))?;
                let position_value = graph
                    .value(inst.inputs[2])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[2]))?;
                let position = position_value
                    .var
                    .constant_bits()
                    .and_then(|bits| u32::try_from(bits).ok())
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[2]))?;
                let root_bits = binding_for_value(root_value)?.width_bits;
                let lane_bits = binding_for_value(lane_value)?.width_bits;
                if root_bits != output.width_bits
                    || position
                        .checked_add(lane_bits)
                        .is_none_or(|end| end > root_bits)
                {
                    return Err(MachineBuildError::WidthMismatch {
                        inst: inst.id,
                        expected_bits: output.width_bits,
                        actual_bits: root_bits,
                    });
                }
                let root = self.intern_value(root_value)?;
                let lane = self.intern_value(lane_value)?;
                let position_expr = self.intern_value(position_value)?;
                self.record_whole_use(graph, inst, 0)?;
                self.record_whole_use(graph, inst, 1)?;
                self.record_whole_use(graph, inst, 2)?;
                Ok((
                    unsigned,
                    MachineExprKind::InsertLane {
                        root,
                        lane,
                        position: position_expr,
                        lsb_bits: position,
                        width_bits: lane_bits,
                    },
                ))
            }
            SSAOp::Select { .. } => {
                if inst.inputs.len() != 3 {
                    return Err(MachineBuildError::WrongOperandCount {
                        inst: inst.id,
                        expected: 3,
                        actual: inst.inputs.len(),
                    });
                }
                let condition_value = graph
                    .value(inst.inputs[0])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[0]))?;
                let condition = self.intern_boolean_value(graph, condition_value, inst.id)?;
                let if_true_value = graph
                    .value(inst.inputs[1])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[1]))?;
                let if_false_value = graph
                    .value(inst.inputs[2])
                    .ok_or(MachineBuildError::MissingGraphValue(inst.inputs[2]))?;
                let if_true = self.intern_value_with_type(if_true_value, unsigned)?;
                let if_false = self.intern_value_with_type(if_false_value, unsigned)?;
                self.record_whole_use(graph, inst, 0)?;
                self.record_whole_use(graph, inst, 1)?;
                self.record_whole_use(graph, inst, 2)?;
                Ok((
                    unsigned,
                    MachineExprKind::Select {
                        condition,
                        if_true,
                        if_false,
                    },
                ))
            }
            // A call's definition of a register is not computed here. The
            // callee wrote it, and what this function knows is the machine
            // location it arrived in -- which is what `Source` says, and what
            // an entry parameter already uses.
            SSAOp::CallDefine { .. } => {
                let value = inst.output.and_then(|output| graph.value(output)).ok_or(
                    MachineBuildError::UnsupportedOperation {
                        inst: inst.id,
                        op: Box::new(op.clone()),
                    },
                )?;
                Ok((
                    unsigned,
                    MachineExprKind::Source {
                        binding: output,
                        storage: value.canonical_storage,
                    },
                ))
            }
            _ => Err(MachineBuildError::UnsupportedOperation {
                inst: inst.id,
                op: Box::new(op.clone()),
            }),
        }
    }
}
