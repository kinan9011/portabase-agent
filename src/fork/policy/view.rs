//! Policy view of a rendered compose document (W17-ii E4, ADR-015 D-2). The FULL render never leaves the agent: every non-null scalar under
//!   services.*.{environment, labels, annotations, command, entrypoint, healthcheck, build, secrets, configs}, every key starting `x-` at any level,
//!   top-level secrets.*.{content, environment} and configs.*.{content, environment}
//! is replaced by `""` (keys, nulls, arrays and structure stay). The engine never reads those fields, so `verdict(view) == verdict(full)` (proved by a test over
//! all 64 rendered vectors). Must stay identical to the dashboard's `restore-tasks/view.ts` (`isPolicyView` re-checks it).
use super::rendered::{MAX_BYTES, MAX_DEPTH, json_too_deep};
use serde_json::{Map, Value};

#[derive(Debug, PartialEq, Eq)]
pub enum ViewError {
    TooLarge,
    TooDeep,
    NotJson,
}

const SERVICE_BLANKED: [&str; 9] = ["environment", "labels", "annotations", "command", "entrypoint", "healthcheck", "build", "secrets", "configs"];
const TOP_BLANKED: [&str; 2] = ["content", "environment"];

fn blank_scalars(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(blank_scalars).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), blank_scalars(x))).collect()),
        Value::Null => Value::Null,
        _ => Value::String(String::new()),
    }
}
fn blank_extensions(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(blank_extensions).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), if k.starts_with("x-") { blank_scalars(x) } else { blank_extensions(x) })).collect()),
        other => other.clone(),
    }
}
pub fn blank_policy_view(doc: &Value) -> Value {
    let d = blank_extensions(doc);
    let Value::Object(mut out) = d else { return d };
    if let Some(Value::Object(services)) = out.get("services").cloned() {
        let mapped: Map<String, Value> = services
            .into_iter()
            .map(|(name, svc)| match svc {
                Value::Object(mut s) => {
                    for k in SERVICE_BLANKED {
                        if let Some(x) = s.get(k).cloned() {
                            s.insert(k.into(), blank_scalars(&x));
                        }
                    }
                    (name, Value::Object(s))
                }
                other => (name, other),
            })
            .collect();
        out.insert("services".into(), Value::Object(mapped));
    }
    for top in ["secrets", "configs"] {
        if let Some(Value::Object(defs)) = out.get(top).cloned() {
            let mapped: Map<String, Value> = defs
                .into_iter()
                .map(|(name, def)| match def {
                    Value::Object(mut o) => {
                        for k in TOP_BLANKED {
                            if let Some(x) = o.get(k).cloned() {
                                o.insert(k.into(), blank_scalars(&x));
                            }
                        }
                        (name, Value::Object(o))
                    }
                    other => (name, other),
                })
                .collect();
            out.insert(top.into(), Value::Object(mapped));
        }
    }
    Value::Object(out)
}

/// bytes of the full render in → bytes of its policy view out (deterministic: serde_json maps are sorted).
pub fn policy_view(full: &[u8]) -> Result<Vec<u8>, ViewError> {
    if full.len() > MAX_BYTES {
        return Err(ViewError::TooLarge);
    }
    if json_too_deep(full, MAX_DEPTH) {
        return Err(ViewError::TooDeep);
    }
    let doc: Value = serde_json::from_slice(full).map_err(|_| ViewError::NotJson)?;
    serde_json::to_vec(&blank_policy_view(&doc)).map_err(|_| ViewError::NotJson)
}
