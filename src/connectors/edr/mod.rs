#![allow(dead_code)]

pub mod webhook;

use std::collections::HashMap;

use crate::connectors::edr::webhook::GenericWebhookAdapter;
use crate::connectors::traits::EDRAdapter;

pub fn default_registry() -> HashMap<String, Box<dyn EDRAdapter>> {
    let mut registry: HashMap<String, Box<dyn EDRAdapter>> = HashMap::new();
    registry.insert("generic".to_string(), Box::new(GenericWebhookAdapter));
    registry
}
