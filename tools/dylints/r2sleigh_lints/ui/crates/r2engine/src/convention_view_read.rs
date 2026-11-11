#![allow(dead_code)]

mod source {
    #[derive(PartialEq, Eq)]
    pub struct SourceConventionSlots {
        argument_slots: Vec<u32>,
    }

    // The view's own impl is the view.
    impl SourceConventionSlots {
        pub fn new() -> Self {
            Self { argument_slots: Vec::new() }
        }

        pub fn argument_slots(&self) -> &[u32] {
            &self.argument_slots
        }
    }

    pub struct Context {
        slots: Option<SourceConventionSlots>,
    }

    impl Context {
        pub fn convention_slots(&self) -> Option<&SourceConventionSlots> {
            self.slots.as_ref()
        }
    }

    pub struct FunctionTypeFacts {
        pub callconv: Option<String>,
    }

    pub struct RegisterIdentity {
        argument_registers: Vec<String>,
    }

    impl RegisterIdentity {
        pub fn argument_registers(&self) -> &[String] {
            &self.argument_registers
        }
    }

    // The holder reads the view; its derived `Eq` restates the field and is not a second reader.
    #[derive(PartialEq, Eq)]
    pub struct Holder {
        pub slots: SourceConventionSlots,
    }

    pub struct ConventionModel;

    impl ConventionModel {
        // The model's own `argument_registers` is the owner, not a view.
        pub fn argument_registers(&self) -> Vec<u32> {
            Vec::new()
        }
    }
}

use source::{ConventionModel, Context, FunctionTypeFacts, RegisterIdentity};

// The accessor chain never names the view.
fn count(context: &Context) -> usize {
    context
        .convention_slots()
        .map_or(0, |slots| slots.argument_slots().len())
}

fn spelled(facts: &FunctionTypeFacts) -> Option<String> {
    facts.callconv.clone()
}

fn built() -> FunctionTypeFacts {
    FunctionTypeFacts { callconv: None }
}

fn unpacked(facts: FunctionTypeFacts) -> bool {
    let FunctionTypeFacts { callconv } = facts;
    callconv.is_some()
}

fn first_argument(identity: &RegisterIdentity) -> Option<&String> {
    identity.argument_registers().first()
}

fn modelled(model: &ConventionModel) -> usize {
    model.argument_registers().len()
}

#[cfg(test)]
mod tests {
    fn a_fixture_may_read(context: &super::Context) -> usize {
        super::count(context) + context.convention_slots().map_or(0, |slots| slots.argument_slots().len())
    }
}

fn main() {}
