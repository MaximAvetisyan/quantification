pub mod config;
mod s1;

pub use s1::{Role, Span};
pub mod benches {
    pub use crate::s1::benches::*;
}
pub mod locator {
    pub use crate::s1::locator::*;
}
