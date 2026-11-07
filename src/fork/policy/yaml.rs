//! YAML layer of the raw compose read-scope check (ADR-015 D-3, E5): a port of `parseYamlLimited` (dashboard `inventory/compose-yaml.ts`, `yaml` package with
//! `{uniqueKeys: true, merge: true, version: "1.2", schema: "core"}`) over yaml-rust2 EVENTS (never its loader). Semantics that matter for the policy:
//! exactly one document, duplicate keys refused, every tag except the YAML core `!!str|int|float|bool|null|seq|map` refused (so compose `!reset` / `!override` and
//! `!!python/...` are `yaml_invalid`), merge keys (`<<`) applied, alias count bounded with the `yaml` package's formula, node / depth / indent limits.
use std::collections::HashMap;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YamlReject {
    TooLarge,
    TooDeep,
    TooManyNodes,
    AliasLimit,
    Syntax,
    Unsupported,
    DuplicateKey,
    NotAMapping,
}
impl YamlReject {
    /// The TS `REASON` table of `raw.ts`.
    pub fn reason(self) -> &'static str {
        match self {
            YamlReject::TooLarge | YamlReject::TooDeep | YamlReject::TooManyNodes | YamlReject::AliasLimit => "limits",
            _ => "yaml_invalid",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct YamlLimits {
    pub max_bytes: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_alias_count: u64,
    pub max_indent: usize,
}
/// `RESTORE_YAML_LIMITS` of raw.ts (W07 limits with `maxAliasCount` 100); `max_bytes` is lowered by the rule file's `raw_read_scope.max_bytes`.
pub const RESTORE_YAML_LIMITS: YamlLimits = YamlLimits { max_bytes: 256 * 1024, max_nodes: 20_000, max_depth: 24, max_alias_count: 100, max_indent: 200 };
const OUTPUT_CAP: usize = 2_000_000;

impl Node {
    pub fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn is_map(&self) -> bool {
        matches!(self, Node::Map(_))
    }
    /// `JSON.stringify` of the node (source key order); NaN / ±inf serialise as `null` like JS.
    pub fn to_json(&self) -> String {
        match self {
            Node::Null => "null".into(),
            Node::Bool(b) => b.to_string(),
            Node::Int(i) => i.to_string(),
            Node::Float(f) if f.is_finite() => {
                if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", *f as i64) } else { format!("{f}") }
            }
            Node::Float(_) => "null".into(),
            Node::Str(s) => serde_json::to_string(s).unwrap_or_default(),
            Node::Seq(v) => format!("[{}]", v.iter().map(Node::to_json).collect::<Vec<_>>().join(",")),
            Node::Map(m) => format!("{{{}}}", m.iter().map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap_or_default(), v.to_json())).collect::<Vec<_>>().join(",")),
        }
    }
    fn key_string(&self) -> String {
        match self {
            Node::Str(s) => s.clone(),
            Node::Null => "null".into(),
            Node::Bool(b) => b.to_string(),
            Node::Int(i) => i.to_string(),
            Node::Float(_) => self.to_json(),
            _ => self.to_json(),
        }
    }
}

/// string-aware-free bracket depth + indent pre-scan of the TS `nestingTooDeep` (same naive scan, on purpose).
fn nesting_too_deep(text: &str, l: &YamlLimits) -> bool {
    let (mut depth, mut line_start, mut indent) = (0usize, true, 0usize);
    for ch in text.chars() {
        if ch == '\n' {
            line_start = true;
            indent = 0;
            continue;
        }
        if line_start && ch == ' ' {
            indent += 1;
            if indent > l.max_indent {
                return true;
            }
            continue;
        }
        line_start = false;
        if ch == '[' || ch == '{' {
            depth += 1;
            if depth > l.max_depth {
                return true;
            }
        } else if ch == ']' || ch == '}' {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

// ---- YAML 1.2 core schema scalar resolution (plain scalars only) -------------------------------------------------------------------------
fn all(s: &str, f: impl Fn(char) -> bool) -> bool {
    !s.is_empty() && s.chars().all(f)
}
fn resolve_plain(s: &str) -> Node {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return Node::Null,
        "true" | "True" | "TRUE" => return Node::Bool(true),
        "false" | "False" | "FALSE" => return Node::Bool(false),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => return Node::Float(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => return Node::Float(f64::NEG_INFINITY),
        ".nan" | ".NaN" | ".NAN" => return Node::Float(f64::NAN),
        _ => {}
    }
    let body = s.strip_prefix(['-', '+']).unwrap_or(s);
    if all(body, |c| c.is_ascii_digit()) {
        return s.parse::<i64>().map(Node::Int).unwrap_or_else(|_| Node::Float(s.parse::<f64>().unwrap_or(f64::NAN)));
    }
    if let Some(o) = s.strip_prefix("0o") {
        if all(o, |c| ('0'..='7').contains(&c)) {
            if let Ok(i) = i64::from_str_radix(o, 8) {
                return Node::Int(i);
            }
        }
    }
    if let Some(h) = s.strip_prefix("0x") {
        if all(h, |c| c.is_ascii_hexdigit()) {
            if let Ok(i) = i64::from_str_radix(h, 16) {
                return Node::Int(i);
            }
        }
    }
    if is_float(body) {
        if let Ok(f) = s.parse::<f64>() {
            return Node::Float(f);
        }
    }
    Node::Str(s.to_string())
}
/// `(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?` (sign already stripped)
fn is_float(b: &str) -> bool {
    let (mant, exp) = match b.find(['e', 'E']) {
        Some(i) => (&b[..i], Some(&b[i + 1..])),
        None => (b, None),
    };
    if let Some(e) = exp {
        let e = e.strip_prefix(['-', '+']).unwrap_or(e);
        if !all(e, |c| c.is_ascii_digit()) {
            return false;
        }
    }
    match mant.split_once('.') {
        None => all(mant, |c| c.is_ascii_digit()),
        Some((i, f)) => (i.is_empty() && all(f, |c| c.is_ascii_digit())) || (all(i, |c| c.is_ascii_digit()) && f.chars().all(|c| c.is_ascii_digit())),
    }
}

// ---- event → arena -------------------------------------------------------------------------------------------------------------------------
enum Raw {
    /// resolved scalar, `merge` = plain, untagged `<<`
    Scalar(Node, bool),
    Seq(Vec<usize>),
    Map(Vec<(usize, usize)>),
    Alias(usize),
}
enum Frame {
    Seq { items: Vec<usize>, anchor: usize },
    Map { pairs: Vec<(usize, usize)>, key: Option<usize>, anchor: usize },
}
struct Receiver {
    l: YamlLimits,
    nodes: Vec<Raw>,
    anchors: HashMap<usize, usize>,
    stack: Vec<Frame>,
    root: Option<usize>,
    docs: usize,
    count: usize,
    err: Option<YamlReject>,
}
const CORE: &str = "tag:yaml.org,2002:";

impl Receiver {
    fn fail(&mut self, e: YamlReject) {
        if self.err.is_none() {
            self.err = Some(e);
        }
    }
    fn bump(&mut self, n: usize) -> bool {
        self.count += n;
        if self.count > self.l.max_nodes {
            self.fail(YamlReject::TooManyNodes);
            return false;
        }
        true
    }
    fn add(&mut self, r: Raw, anchor: usize) -> usize {
        self.nodes.push(r);
        let idx = self.nodes.len() - 1;
        if anchor != 0 {
            self.anchors.insert(anchor, idx);
        }
        idx
    }
    fn attach(&mut self, idx: usize) {
        match self.stack.last_mut() {
            None => self.root = Some(idx),
            Some(Frame::Seq { items, .. }) => items.push(idx),
            Some(Frame::Map { pairs, key, .. }) => match key.take() {
                None => *key = Some(idx),
                Some(k) => pairs.push((k, idx)),
            },
        }
    }
    fn core_tag(tag: &Option<yaml_rust2::parser::Tag>, allowed: &[&str]) -> Result<Option<String>, YamlReject> {
        match tag {
            None => Ok(None),
            Some(t) if t.handle == CORE && allowed.contains(&t.suffix.as_str()) => Ok(Some(t.suffix.clone())),
            Some(_) => Err(YamlReject::Unsupported),
        }
    }
}

impl MarkedEventReceiver for Receiver {
    fn on_event(&mut self, ev: Event, _mark: Marker) {
        if self.err.is_some() {
            return;
        }
        match ev {
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
            Event::DocumentStart => {
                self.docs += 1;
                if self.docs > 1 {
                    self.fail(YamlReject::Syntax);
                }
            }
            Event::Scalar(s, style, aid, tag) => {
                if self.stack.len() > self.l.max_depth {
                    return self.fail(YamlReject::TooDeep);
                }
                if !self.bump(1) {
                    return;
                }
                let node = match Self::core_tag(&tag, &["str", "int", "float", "bool", "null"]) {
                    Err(e) => return self.fail(e),
                    Ok(Some(t)) if t == "str" => Node::Str(s.clone()),
                    Ok(Some(t)) => {
                        let n = resolve_plain(&s);
                        let ok = matches!((t.as_str(), &n), ("int", Node::Int(_)) | ("float", Node::Float(_) | Node::Int(_)) | ("bool", Node::Bool(_)) | ("null", Node::Null));
                        if !ok {
                            return self.fail(YamlReject::Unsupported);
                        }
                        n
                    }
                    Ok(None) if style == TScalarStyle::Plain => resolve_plain(&s),
                    Ok(None) => Node::Str(s.clone()),
                };
                let merge = tag.is_none() && style == TScalarStyle::Plain && s == "<<";
                let idx = self.add(Raw::Scalar(node, merge), 0);
                if aid != 0 {
                    self.anchors.insert(aid, idx);
                }
                self.attach(idx);
            }
            Event::Alias(id) => {
                if !self.bump(1) {
                    return;
                }
                match self.anchors.get(&id).copied() {
                    None => self.fail(YamlReject::Syntax), // unresolved alias (anchors are registered when their node is COMPLETE: no self reference)
                    Some(t) => {
                        let idx = self.add(Raw::Alias(t), 0);
                        self.attach(idx);
                    }
                }
            }
            Event::SequenceStart(aid, tag) => {
                if self.stack.len() > self.l.max_depth {
                    return self.fail(YamlReject::TooDeep);
                }
                if let Err(e) = Self::core_tag(&tag, &["seq"]) {
                    return self.fail(e);
                }
                if self.bump(1) {
                    self.stack.push(Frame::Seq { items: vec![], anchor: aid });
                }
            }
            Event::MappingStart(aid, tag) => {
                if self.stack.len() > self.l.max_depth {
                    return self.fail(YamlReject::TooDeep);
                }
                if let Err(e) = Self::core_tag(&tag, &["map"]) {
                    return self.fail(e);
                }
                if self.bump(1) {
                    self.stack.push(Frame::Map { pairs: vec![], key: None, anchor: aid });
                }
            }
            Event::SequenceEnd => {
                if let Some(Frame::Seq { items, anchor }) = self.stack.pop() {
                    let idx = self.add(Raw::Seq(items), anchor);
                    self.attach(idx);
                } else {
                    self.fail(YamlReject::Syntax);
                }
            }
            Event::MappingEnd => {
                if let Some(Frame::Map { pairs, key, anchor }) = self.stack.pop() {
                    if key.is_some() || !self.bump(pairs.len()) {
                        return self.fail(YamlReject::Syntax);
                    }
                    let idx = self.add(Raw::Map(pairs), anchor);
                    self.attach(idx);
                } else {
                    self.fail(YamlReject::Syntax);
                }
            }
        }
    }
}

// ---- arena → Node (the `toJS` of the yaml package: alias counting, merge keys, duplicate keys) ------------------------------------------------
struct Conv<'a> {
    nodes: &'a [Raw],
    /// anchored arena index → (count, aliasCount), count starts at 1 when the node itself is converted (yaml `toJS`)
    data: HashMap<usize, (u64, u64)>,
    res: HashMap<usize, Node>,
    anchored: std::collections::HashSet<usize>,
    l: YamlLimits,
    out: usize,
}
impl Conv<'_> {
    fn weight(&self, idx: usize) -> u64 {
        match &self.nodes[idx] {
            Raw::Scalar(..) => 1,
            Raw::Alias(t) => self.data.get(t).map(|(c, a)| c * a).unwrap_or(0),
            Raw::Seq(items) => items.iter().map(|i| self.weight(*i)).max().unwrap_or(0),
            Raw::Map(pairs) => pairs.iter().map(|(k, v)| self.weight(*k).max(self.weight(*v))).max().unwrap_or(0),
        }
    }
    fn register(&mut self, idx: usize) {
        if self.anchored.contains(&idx) {
            self.data.insert(idx, (1, 0));
        }
    }
    fn keep(&mut self, idx: usize, n: &Node) {
        if self.anchored.contains(&idx) {
            self.res.insert(idx, n.clone());
        }
    }
    fn conv(&mut self, idx: usize, depth: usize) -> Result<Node, YamlReject> {
        if depth > self.l.max_depth {
            return Err(YamlReject::TooDeep);
        }
        self.out += 1;
        if self.out > OUTPUT_CAP {
            return Err(YamlReject::TooManyNodes);
        }
        self.register(idx);
        let node = match &self.nodes[idx] {
            Raw::Scalar(n, _) => n.clone(),
            Raw::Alias(t) => {
                let t = *t;
                let w = self.weight(t);
                let d = self.data.get_mut(&t).ok_or(YamlReject::Syntax)?;
                d.0 += 1;
                if d.1 == 0 {
                    d.1 = w;
                }
                if d.0.saturating_mul(d.1) > self.l.max_alias_count {
                    return Err(YamlReject::AliasLimit);
                }
                self.res.get(&t).cloned().ok_or(YamlReject::Syntax)?
            }
            Raw::Seq(items) => {
                let items = items.clone();
                let mut out = Vec::with_capacity(items.len());
                for i in items {
                    out.push(self.conv(i, depth + 1)?);
                }
                Node::Seq(out)
            }
            Raw::Map(pairs) => {
                let pairs = pairs.clone();
                self.conv_map(&pairs, depth)?
            }
        };
        self.keep(idx, &node);
        Ok(node)
    }
    fn conv_map(&mut self, pairs: &[(usize, usize)], depth: usize) -> Result<Node, YamlReject> {
        let mut out: Vec<(String, Node)> = Vec::new();
        let mut seen: Vec<&Node> = Vec::new();
        for (k, v) in pairs {
            if let Raw::Scalar(kn, is_merge) = &self.nodes[*k] {
                if seen.iter().any(|s| *s == kn && !matches!(kn, Node::Float(f) if f.is_nan())) {
                    return Err(YamlReject::DuplicateKey);
                }
                seen.push(kn);
                if *is_merge {
                    self.merge_into(&mut out, *v, depth)?;
                    continue;
                }
            }
            let key = self.conv(*k, depth + 1)?;
            let val = self.conv(*v, depth + 1)?;
            let ks = key.key_string();
            match out.iter_mut().find(|(e, _)| *e == ks) {
                Some(slot) => slot.1 = val,
                None => out.push((ks, val)),
            }
        }
        Ok(Node::Map(out))
    }
    /// `<<: *a` / `<<: [*a, *b]` / `<<: {inline}`: add keys that are not present yet; every source must be a map (else yaml throws ⇒ syntax).
    fn merge_into(&mut self, out: &mut Vec<(String, Node)>, v: usize, depth: usize) -> Result<(), YamlReject> {
        let sources: Vec<usize> = match &self.nodes[v] {
            Raw::Seq(items) => items.clone(),
            _ => vec![v],
        };
        for s in sources {
            let src = match &self.nodes[s] {
                Raw::Alias(t) => {
                    let t = *t;
                    self.res.get(&t).cloned().ok_or(YamlReject::Syntax)?
                }
                Raw::Map(_) => self.conv(s, depth + 1)?,
                _ => return Err(YamlReject::Syntax),
            };
            match src {
                Node::Map(entries) => {
                    for (k, val) in entries {
                        if !out.iter().any(|(e, _)| *e == k) {
                            out.push((k, val));
                        }
                    }
                }
                _ => return Err(YamlReject::Syntax),
            }
        }
        Ok(())
    }
}

fn parse_events(text: &str, l: &YamlLimits) -> Result<Node, YamlReject> {
    let mut r = Receiver { l: *l, nodes: vec![], anchors: HashMap::new(), stack: vec![], root: None, docs: 0, count: 0, err: None };
    let mut p = Parser::new_from_str(text);
    if p.load(&mut r, true).is_err() {
        return Err(r.err.unwrap_or(YamlReject::Syntax));
    }
    if let Some(e) = r.err {
        return Err(e);
    }
    let Some(root) = r.root else { return Ok(Node::Null) };
    let anchored: std::collections::HashSet<usize> = r.anchors.values().copied().collect();
    let mut c = Conv { nodes: &r.nodes, data: HashMap::new(), res: HashMap::new(), anchored, l: *l, out: 0 };
    c.conv(root, 0)
}

/// One YAML document under explicit limits. Never panics (the event parser's internal assertions are caught and reported as `Syntax`).
pub fn parse_yaml_limited(text: &str, l: &YamlLimits) -> Result<Node, YamlReject> {
    if text.len() > l.max_bytes {
        return Err(YamlReject::TooLarge);
    }
    if nesting_too_deep(text, l) {
        return Err(YamlReject::TooDeep);
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse_events(text, l))).unwrap_or(Err(YamlReject::Syntax))
}
