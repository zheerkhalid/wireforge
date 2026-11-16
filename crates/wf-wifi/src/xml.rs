//! A small, tolerant XML reader: just enough for WLAN profile documents.
//!
//! It keeps element names (namespace prefixes dropped), text (entities and
//! CDATA decoded) and nesting. Attributes, comments, processing instructions
//! and DOCTYPE declarations are skipped. Nothing here derives `Debug`, because
//! the text of a profile contains the Wi-Fi key.

/// One element.
#[derive(Clone, Default)]
pub(crate) struct Node {
    /// Local name (no namespace prefix).
    pub name: String,
    /// The element's own text, entities decoded, not trimmed.
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    /// First direct child with this local name (ASCII case-insensitive).
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// All direct children with this local name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children
            .iter()
            .filter(move |c| c.name.eq_ignore_ascii_case(name))
    }

    /// Follows a path of direct children.
    pub fn path(&self, path: &[&str]) -> Option<&Node> {
        let mut node = self;
        for name in path {
            node = node.child(name)?;
        }
        Some(node)
    }

    /// First descendant (depth first) with this local name.
    pub fn find(&self, name: &str) -> Option<&Node> {
        let mut pending: Vec<&Node> = self.children.iter().rev().collect();
        while let Some(node) = pending.pop() {
            if node.name.eq_ignore_ascii_case(name) {
                return Some(node);
            }
            pending.extend(node.children.iter().rev());
        }
        None
    }

    /// The text with surrounding white space removed.
    pub fn trimmed(&self) -> &str {
        self.text.trim()
    }
}

const MAX_DEPTH: usize = 64;

fn local_name(raw: &str) -> &str {
    match raw.rfind(':') {
        Some(p) => raw.get(p + 1..).unwrap_or(raw),
        None => raw,
    }
}

fn attach(stack: &mut [Node], root: &mut Option<Node>, node: Node) -> Result<(), String> {
    match stack.last_mut() {
        Some(parent) => parent.children.push(node),
        None => {
            if root.is_some() {
                return Err("more than one root element".into());
            }
            *root = Some(node);
        }
    }
    Ok(())
}

/// Parses a document and returns its root element.
pub(crate) fn parse(input: &str) -> Result<Node, String> {
    let s = input.trim_start_matches('\u{feff}');
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;

    while i < bytes.len() {
        let rest = s.get(i..).ok_or("damaged text")?;
        if !rest.starts_with('<') {
            let end = rest.find('<').unwrap_or(rest.len());
            let raw = rest.get(..end).unwrap_or("");
            match stack.last_mut() {
                Some(top) => top.text.push_str(&decode_entities(raw)),
                None => {
                    if !raw
                        .trim_matches(|c: char| c.is_whitespace() || c == '\0')
                        .is_empty()
                    {
                        return Err("text outside the root element".into());
                    }
                }
            }
            i += end.max(1);
            continue;
        }
        if rest.starts_with("<!--") {
            let end = rest.find("-->").ok_or("a comment is not closed")?;
            i += end + 3;
        } else if rest.starts_with("<![CDATA[") {
            let end = rest.find("]]>").ok_or("a CDATA section is not closed")?;
            let top = stack.last_mut().ok_or("text outside the root element")?;
            top.text.push_str(rest.get(9..end).unwrap_or(""));
            i += end + 3;
        } else if rest.starts_with("<?") {
            let end = rest.find("?>").ok_or("a declaration is not closed")?;
            i += end + 2;
        } else if rest.starts_with("<!") {
            let end = rest.find('>').ok_or("a declaration is not closed")?;
            i += end + 1;
        } else if rest.starts_with("</") {
            let end = rest.find('>').ok_or("a closing tag is not closed")?;
            let name = local_name(rest.get(2..end).unwrap_or("").trim());
            let node = stack.pop().ok_or("a closing tag has no opening tag")?;
            if node.name != name {
                return Err("a closing tag does not match its opening tag".into());
            }
            attach(&mut stack, &mut root, node)?;
            i += end + 1;
        } else {
            // A start tag: find its end, skipping over quoted attribute values.
            let mut quote: Option<u8> = None;
            let mut end = None;
            for (offset, &b) in rest.as_bytes().iter().enumerate().skip(1) {
                match quote {
                    Some(q) => {
                        if b == q {
                            quote = None;
                        }
                    }
                    None => match b {
                        b'"' | b'\'' => quote = Some(b),
                        b'>' => {
                            end = Some(offset);
                            break;
                        }
                        _ => {}
                    },
                }
            }
            let end = end.ok_or("an opening tag is not closed")?;
            let inner = rest.get(1..end).unwrap_or("");
            let self_closing = inner.ends_with('/');
            let inner = inner.trim_end_matches('/');
            let raw_name = inner.split(char::is_whitespace).next().unwrap_or("");
            if raw_name.is_empty() {
                return Err("an element has no name".into());
            }
            if stack.is_empty() && root.is_some() {
                return Err("more than one root element".into());
            }
            if stack.len() >= MAX_DEPTH {
                return Err("elements are nested too deeply".into());
            }
            let node = Node {
                name: local_name(raw_name).to_string(),
                ..Node::default()
            };
            if self_closing {
                attach(&mut stack, &mut root, node)?;
            } else {
                stack.push(node);
            }
            i += end + 1;
        }
    }
    if !stack.is_empty() {
        return Err("the document ends inside an element".into());
    }
    root.ok_or_else(|| "there is no root element".to_string())
}

/// Replaces `&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`, `&#NN;` and `&#xNN;`.
/// Anything that is not a known reference is kept as written.
pub(crate) fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        out.push_str(rest.get(..amp).unwrap_or(""));
        let after = rest.get(amp + 1..).unwrap_or("");
        let decoded = after.find(';').filter(|&semi| semi <= 10).and_then(|semi| {
            let name = after.get(..semi)?;
            let ch = match name {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let code = if let Some(hex) =
                        name.strip_prefix("#x").or_else(|| name.strip_prefix("#X"))
                    {
                        u32::from_str_radix(hex, 16).ok()?
                    } else {
                        name.strip_prefix('#')?.parse::<u32>().ok()?
                    };
                    char::from_u32(code)?
                }
            };
            Some((ch, semi))
        });
        match decoded {
            Some((ch, semi)) => {
                out.push(ch);
                rest = after.get(semi + 1..).unwrap_or("");
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_namespaces_and_attributes() {
        let doc = r#"<?xml version="1.0"?>
            <!-- a comment -->
            <a:root xmlns:a="urn:x" note="a > b">
                <a:one>1</a:one>
                <two attr='x'/>
                <three><inner>deep</inner></three>
            </a:root>"#;
        let root = parse(doc).unwrap_or_default();
        assert_eq!(root.name, "root");
        assert_eq!(root.child("one").map(|n| n.trimmed()), Some("1"));
        assert!(root.child("two").is_some());
        assert_eq!(root.find("inner").map(|n| n.trimmed()), Some("deep"));
        assert_eq!(
            root.path(&["three", "inner"]).map(|n| n.trimmed()),
            Some("deep")
        );
        assert_eq!(root.children_named("one").count(), 1);
    }

    #[test]
    fn entities_and_cdata() {
        assert_eq!(
            decode_entities("a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos; &#x41;&#66;"),
            "a & b <c> \"d\" 'e' AB"
        );
        assert_eq!(
            decode_entities("fish & chips &unknown; &"),
            "fish & chips &unknown; &"
        );
        assert_eq!(decode_entities("&#x1F600;"), "\u{1F600}");
        assert_eq!(decode_entities("&#xD800;"), "&#xD800;");
        let root = parse("<r>one <![CDATA[<two> & ]]>three</r>").unwrap_or_default();
        assert_eq!(root.text, "one <two> & three");
    }

    #[test]
    fn malformed_documents_are_errors() {
        for doc in [
            "",
            "   ",
            "plain text",
            "<a>",
            "<a><b></a></b>",
            "</a>",
            "<a></a><b></b>",
            "<a",
            "<a><!-- never closed </a>",
            "<a><![CDATA[ never closed </a>",
            "<>",
            "<a></a>trailing",
        ] {
            assert!(parse(doc).is_err(), "{doc:?} should be rejected");
        }
    }

    #[test]
    fn deep_nesting_is_refused_not_overflowed() {
        let doc = "<a>".repeat(10_000);
        assert!(parse(&doc).is_err());
    }
}
