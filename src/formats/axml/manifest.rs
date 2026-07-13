//! High-level `AndroidManifest.xml` analysis built on the AXML event stream.
//!
//! Turns the raw XML into the security-relevant view: package, requested
//! permissions, and the exported components (with their intent filters) that
//! define an app's externally reachable attack surface.

use super::types::XmlEvent;

/// The Android resource namespace URI that prefixes framework attributes.
pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// Kind of Android component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    Activity,
    ActivityAlias,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    fn from_element(name: &str) -> Option<Self> {
        match name {
            "activity" => Some(Self::Activity),
            "activity-alias" => Some(Self::ActivityAlias),
            "service" => Some(Self::Service),
            "receiver" => Some(Self::Receiver),
            "provider" => Some(Self::Provider),
            _ => None,
        }
    }
}

/// An `<intent-filter>` distilled to the fields that matter for reachability
/// and deep-link analysis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    /// `scheme://host` (or partial) tuples from `<data>` elements — the deep
    /// links that route external input into the component.
    pub data: Vec<String>,
}

/// A declared component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub kind: ComponentKind,
    pub name: String,
    /// The explicit `android:exported` value, if the manifest set one.
    pub exported: Option<bool>,
    /// `android:permission` guarding the component, if any.
    pub permission: Option<String>,
    /// For providers: the `android:authorities` value, if any.
    pub authorities: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

impl Component {
    /// Whether the component is reachable by other apps.
    ///
    /// Uses the explicit `android:exported` when present; otherwise applies the
    /// legacy default (exported iff it declares at least one intent filter).
    pub fn is_exported(&self) -> bool {
        self.exported.unwrap_or(!self.intent_filters.is_empty())
    }

    /// Deep links exposed by this component across all its intent filters.
    pub fn deep_links(&self) -> Vec<&str> {
        self.intent_filters
            .iter()
            .flat_map(|f| f.data.iter().map(|s| s.as_str()))
            .collect()
    }
}

/// Distilled manifest facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestSummary {
    pub package: Option<String>,
    pub uses_permissions: Vec<String>,
    pub components: Vec<Component>,
}

impl ManifestSummary {
    /// Build a summary from a parsed AXML event stream.
    pub fn from_events(events: &[XmlEvent]) -> Self {
        let mut summary = ManifestSummary::default();
        // Stack of open component builders keyed by the element depth at which
        // they were opened, so nested elements attach correctly.
        let mut open: Vec<(usize, Component)> = Vec::new();
        let mut in_filter: Option<(usize, IntentFilter)> = None;
        let mut depth = 0usize;

        for ev in events {
            match ev {
                XmlEvent::StartElement { name, attributes } => {
                    let attr = |want: &str| find_attr(attributes, want);

                    match name.as_str() {
                        "manifest" => {
                            // `package` is a plain (non-namespaced) attribute.
                            summary.package = attr("package");
                        }
                        "uses-permission" | "uses-permission-sdk-23" => {
                            if let Some(p) = attr("name") {
                                summary.uses_permissions.push(p);
                            }
                        }
                        "intent-filter" => {
                            in_filter = Some((depth, IntentFilter::default()));
                        }
                        "action" => {
                            if let (Some((_, f)), Some(n)) = (in_filter.as_mut(), attr("name")) {
                                f.actions.push(n);
                            }
                        }
                        "category" => {
                            if let (Some((_, f)), Some(n)) = (in_filter.as_mut(), attr("name")) {
                                f.categories.push(n);
                            }
                        }
                        "data" => {
                            if let Some((_, f)) = in_filter.as_mut() {
                                if let Some(d) = render_data(attributes) {
                                    f.data.push(d);
                                }
                            }
                        }
                        other => {
                            if let Some(kind) = ComponentKind::from_element(other) {
                                open.push((
                                    depth,
                                    Component {
                                        kind,
                                        name: attr("name").unwrap_or_default(),
                                        exported: attr("exported").map(|v| v == "true"),
                                        permission: attr("permission"),
                                        authorities: attr("authorities"),
                                        intent_filters: Vec::new(),
                                    },
                                ));
                            }
                        }
                    }
                    depth += 1;
                }
                XmlEvent::EndElement { name } => {
                    depth = depth.saturating_sub(1);

                    // Close an intent filter opened at this depth.
                    if name == "intent-filter" {
                        if let Some((fdepth, filter)) = in_filter.take() {
                            debug_assert_eq!(fdepth, depth);
                            if let Some((_, comp)) = open.last_mut() {
                                comp.intent_filters.push(filter);
                            }
                        }
                    }

                    // Close a component opened at this depth.
                    if let Some((cdepth, _)) = open.last() {
                        if *cdepth == depth && ComponentKind::from_element(name).is_some() {
                            let (_, comp) = open.pop().unwrap();
                            summary.components.push(comp);
                        }
                    }
                }
            }
        }

        summary
    }

    /// The subset of components reachable by other apps.
    pub fn exported_components(&self) -> Vec<&Component> {
        self.components.iter().filter(|c| c.is_exported()).collect()
    }
}

/// Find an attribute by local name, tolerating both the android namespace and
/// unnamespaced forms (aapt emits `package` unnamespaced but `name` under the
/// android namespace).
fn find_attr(attrs: &[super::types::XmlAttribute], want: &str) -> Option<String> {
    attrs
        .iter()
        .find(|a| a.name == want && (a.namespace.is_empty() || a.namespace == ANDROID_NS))
        .map(|a| a.value.clone())
        // Fall back to any namespace if the lenient match missed.
        .or_else(|| {
            attrs
                .iter()
                .find(|a| a.name == want)
                .map(|a| a.value.clone())
        })
}

/// Render a `<data>` element into a compact `scheme://host[:port][path]` string.
fn render_data(attrs: &[super::types::XmlAttribute]) -> Option<String> {
    let get = |n: &str| find_attr(attrs, n);
    let scheme = get("scheme");
    let host = get("host");
    let port = get("port");
    let path = get("path")
        .or_else(|| get("pathPrefix"))
        .or_else(|| get("pathPattern"));
    let mime = get("mimeType");

    if scheme.is_none() && host.is_none() && mime.is_none() && path.is_none() {
        return None;
    }
    let mut out = String::new();
    if let Some(s) = scheme {
        out.push_str(&s);
        out.push_str("://");
    }
    if let Some(h) = host {
        out.push_str(&h);
    }
    if let Some(p) = port {
        out.push(':');
        out.push_str(&p);
    }
    if let Some(p) = path {
        out.push_str(&p);
    }
    if let Some(m) = mime {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str("mime=");
        out.push_str(&m);
    }
    Some(out)
}
