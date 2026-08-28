//! Markdown transactional email rendering.
//!
//! The site's design principle - everything is expressible as markdown -
//! applied to email. Every transactional email (newsletter excluded) is a
//! markdown document rendered through ONE chrome: centered 22px heading,
//! a single 14px body size, a single black text color, and an optional
//! centered brand logo. The plain-text alternative is derived from the same
//! source, so the two parts can never drift.
//!
//! Two shortcodes cover what markdown cannot say (each on its own line):
//!   {{code:483920}}            - the big monospace one-time-code box
//!   {{button:Label|https://x}} - primary CTA button + fallback paste-link
//!
//! A table whose header cells are all empty renders without a header row -
//! the same borderless key/value grid the public site uses. A blockquote
//! renders as the highlighted callout box. Raw HTML in the source is shown
//! literally, never emitted.

use pulldown_cmark::{Alignment, Event, Options, Parser, Tag, TagEnd};

pub struct RenderedEmail {
    pub html: String,
    pub text: String,
}

const S_BODY: &str = "margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#ffffff;color:#1a1d23;font-size:14px;line-height:1.55;";
const S_H1: &str = "margin:0 0 22px;font-weight:600;font-size:22px;text-align:center;";
const S_H2: &str = "font-size:14px;margin:28px 0 8px;";
const S_P: &str = "margin:0 0 14px;";
const S_A: &str = "color:#2563eb;text-decoration:none;";
const S_TABLE: &str = "width:100%;border-collapse:collapse;margin:0 0 14px;";
const S_TH: &str = "padding:6px 0;border-bottom:1px solid #d8dbe1;font-weight:600;";
const S_TD: &str = "padding:6px 0;vertical-align:top;";
const S_UL: &str = "margin:0 0 14px;padding-left:20px;";
const S_LI: &str = "margin:0 0 4px;";
const S_QUOTE: &str = "background:#eef4ff;border-left:3px solid #2563eb;padding:12px 16px;margin:0 0 18px;";
const S_HR: &str = "border:none;border-top:1px solid #d8dbe1;margin:18px 0;";
const S_CODE_BOX: &str = "margin:0 0 26px;padding:22px 12px;background:#f3f4f6;border-radius:10px;font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:34px;font-weight:600;letter-spacing:10px;color:#1a1d23;text-align:center;";
const S_BUTTON: &str = "display:inline-block;padding:11px 22px;background:#2563eb;color:#ffffff;text-decoration:none;border-radius:8px;font-weight:600;";
const S_CODE_INLINE: &str = "font-family:ui-monospace,Menlo,Consolas,monospace;background:#f3f4f6;padding:1px 5px;border-radius:4px;";

/// Render a markdown email body into the standard chrome. `logo` is the
/// (content id, alt text) of an inline image attached by the caller.
pub fn render(md: &str, logo: Option<(&str, &str)>) -> RenderedEmail {
    let mut html = String::new();
    let mut text = String::new();

    // Shortcode lines split the document; the chunks between them are plain
    // markdown.
    let mut chunk = String::new();
    let flush = |chunk: &mut String, html: &mut String, text: &mut String| {
        if !chunk.trim().is_empty() {
            html.push_str(&md_to_html(chunk));
            text.push_str(&md_to_text(chunk));
        }
        chunk.clear();
    };
    for line in md.lines() {
        let t = line.trim();
        if let Some(code) = t.strip_prefix("{{code:").and_then(|r| r.strip_suffix("}}")) {
            flush(&mut chunk, &mut html, &mut text);
            html.push_str(&format!("<div style=\"{}\">{}</div>", S_CODE_BOX, esc_html(code)));
            text.push_str(&format!("    {}\n\n", code));
        } else if let Some(rest) = t.strip_prefix("{{button:").and_then(|r| r.strip_suffix("}}")) {
            flush(&mut chunk, &mut html, &mut text);
            let (label, url) = rest.split_once('|').unwrap_or((rest, ""));
            html.push_str(&format!(
                "<p style=\"margin:0 0 22px;text-align:center;\"><a href=\"{url}\" style=\"{S_BUTTON}\">{label}</a></p>\
                 <p style=\"{S_P}\">Or paste this into your browser:</p>\
                 <p style=\"margin:0 0 18px;word-break:break-all;\"><a href=\"{url}\" style=\"{S_A}\">{url}</a></p>",
                url = esc_html(url),
                label = esc_html(label),
            ));
            text.push_str(&format!("{}:\n{}\n\n", label, url));
        } else {
            chunk.push_str(line);
            chunk.push('\n');
        }
    }
    flush(&mut chunk, &mut html, &mut text);

    let logo_html = logo
        .map(|(cid, alt)| {
            format!(
                "<div style=\"text-align:center;margin-bottom:28px;\"><img src=\"cid:{}\" alt=\"{}\" style=\"height:72px;display:inline-block;\"></div>",
                esc_html(cid),
                esc_html(alt),
            )
        })
        .unwrap_or_default();

    RenderedEmail {
        html: format!(
            "<!doctype html><html><body style=\"{}\"><div style=\"max-width:600px;margin:0 auto;padding:32px 24px;\">{}{}</div></body></html>",
            S_BODY, logo_html, html,
        ),
        text: text.trim_end().to_string() + "\n",
    }
}

/// Fill a markdown template: `{name}` tokens are replaced from `vars`
/// (unknown tokens stay literal, `{{` shortcode braces are never touched).
/// One conditional rule keeps templates free of logic: a LINE that references
/// a variable which resolves to "" is dropped entirely - that is how the
/// optional support line, thank-you box, and tracking button disappear.
pub fn apply_template(template: &str, vars: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    'line: for line in template.lines() {
        let mut filled = String::with_capacity(line.len());
        let mut rest = line;
        while let Some(i) = rest.find('{') {
            filled.push_str(&rest[..i]);
            let after = &rest[i..];
            if after.starts_with("{{") {
                // Shortcode braces - copy one brace pair and continue inside
                // (a shortcode argument may itself be a {variable}).
                filled.push_str("{{");
                rest = &after[2..];
                continue;
            }
            match after[1..].find(['}', '{']) {
                Some(j) if after.as_bytes()[1 + j] == b'}' => {
                    let name = &after[1..1 + j];
                    if let Some((_, v)) = vars.iter().find(|(k, _)| *k == name) {
                        if v.is_empty() {
                            continue 'line; // drop the whole line
                        }
                        filled.push_str(v);
                    } else {
                        filled.push('{');
                        filled.push_str(name);
                        filled.push('}');
                    }
                    rest = &after[2 + j..];
                }
                _ => {
                    filled.push('{');
                    rest = &after[1..];
                }
            }
        }
        filled.push_str(rest);
        out.push_str(&filled);
        out.push('\n');
    }
    out
}

/// Escape a dynamic value for interpolation into a markdown email body so
/// user-supplied text (product titles, names, addresses) cannot change the
/// document structure.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '|' | '#') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn esc_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn parser(md: &str) -> Parser<'_> {
    Parser::new_ext(md, Options::ENABLE_TABLES)
}

fn align_style(a: &Alignment) -> &'static str {
    match a {
        Alignment::Right => "text-align:right;",
        Alignment::Center => "text-align:center;",
        _ => "text-align:left;",
    }
}

/// Write target: the header buffer while inside a table head (so an
/// all-empty header can be dropped), the output otherwise.
fn tgt<'a>(in_head: bool, head: &'a mut String, out: &'a mut String) -> &'a mut String {
    if in_head { head } else { out }
}

fn md_to_html(md: &str) -> String {
    let mut out = String::new();
    // Table state: alignments for the current table, the cell index, and a
    // buffered header (dropped when every header cell is empty - that is the
    // borderless grid convention).
    let mut aligns: Vec<Alignment> = Vec::new();
    let mut cell = 0usize;
    let mut in_head = false;
    let mut head_buf = String::new();
    let mut head_has_text = false;

    for ev in parser(md) {
        match ev {
            Event::Start(tag) => match tag {
                Tag::Heading { level, .. } => {
                    let h = if level == pulldown_cmark::HeadingLevel::H1 {
                        format!("<h1 style=\"{}\">", S_H1)
                    } else {
                        format!("<h2 style=\"{}\">", S_H2)
                    };
                    tgt(in_head, &mut head_buf, &mut out).push_str(&h);
                }
                Tag::Paragraph => tgt(in_head, &mut head_buf, &mut out).push_str(&format!("<p style=\"{}\">", S_P)),
                Tag::Strong => tgt(in_head, &mut head_buf, &mut out).push_str("<strong>"),
                Tag::Emphasis => tgt(in_head, &mut head_buf, &mut out).push_str("<em>"),
                Tag::Link { dest_url, .. } => {
                    let a = format!("<a href=\"{}\" style=\"{}\">", esc_html(&dest_url), S_A);
                    tgt(in_head, &mut head_buf, &mut out).push_str(&a);
                }
                Tag::List(_) => out.push_str(&format!("<ul style=\"{}\">", S_UL)),
                Tag::Item => out.push_str(&format!("<li style=\"{}\">", S_LI)),
                Tag::BlockQuote(..) => out.push_str(&format!("<div style=\"{}\">", S_QUOTE)),
                Tag::Table(a) => {
                    aligns = a;
                    out.push_str(&format!("<table style=\"{}\">", S_TABLE));
                }
                Tag::TableHead => {
                    in_head = true;
                    head_has_text = false;
                    head_buf.clear();
                    head_buf.push_str("<thead><tr>");
                    cell = 0;
                }
                Tag::TableRow => {
                    out.push_str("<tr>");
                    cell = 0;
                }
                Tag::TableCell => {
                    let style = if in_head { S_TH } else { S_TD };
                    let align = aligns.get(cell).map(align_style).unwrap_or("");
                    let open = format!("<{} style=\"{}{}\">", if in_head { "th" } else { "td" }, style, align);
                    tgt(in_head, &mut head_buf, &mut out).push_str(&open);
                }
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Heading(level) => {
                    let h = if level == pulldown_cmark::HeadingLevel::H1 { "</h1>" } else { "</h2>" };
                    tgt(in_head, &mut head_buf, &mut out).push_str(h);
                }
                TagEnd::Paragraph => tgt(in_head, &mut head_buf, &mut out).push_str("</p>"),
                TagEnd::Strong => tgt(in_head, &mut head_buf, &mut out).push_str("</strong>"),
                TagEnd::Emphasis => tgt(in_head, &mut head_buf, &mut out).push_str("</em>"),
                TagEnd::Link => tgt(in_head, &mut head_buf, &mut out).push_str("</a>"),
                TagEnd::List(_) => out.push_str("</ul>"),
                TagEnd::Item => out.push_str("</li>"),
                TagEnd::BlockQuote(..) => out.push_str("</div>"),
                TagEnd::Table => out.push_str("</tbody></table>"),
                TagEnd::TableHead => {
                    head_buf.push_str("</tr></thead>");
                    in_head = false;
                    if head_has_text {
                        out.push_str(&head_buf);
                    }
                    out.push_str("<tbody>");
                }
                TagEnd::TableRow => out.push_str("</tr>"),
                TagEnd::TableCell => {
                    tgt(in_head, &mut head_buf, &mut out).push_str(if in_head { "</th>" } else { "</td>" });
                    cell += 1;
                }
                _ => {}
            },
            Event::Text(t) => {
                if in_head && !t.trim().is_empty() {
                    head_has_text = true;
                }
                let e = esc_html(&t);
                tgt(in_head, &mut head_buf, &mut out).push_str(&e);
            }
            Event::Code(t) => {
                let c = format!("<code style=\"{}\">{}</code>", S_CODE_INLINE, esc_html(&t));
                tgt(in_head, &mut head_buf, &mut out).push_str(&c);
            }
            Event::SoftBreak => tgt(in_head, &mut head_buf, &mut out).push(' '),
            Event::HardBreak => tgt(in_head, &mut head_buf, &mut out).push_str("<br>"),
            Event::Rule => out.push_str(&format!("<hr style=\"{}\">", S_HR)),
            // Raw HTML is never passed through - show it literally.
            Event::Html(t) | Event::InlineHtml(t) => {
                let e = esc_html(&t);
                tgt(in_head, &mut head_buf, &mut out).push_str(&e);
            }
            _ => {}
        }
    }
    out
}

fn md_to_text(md: &str) -> String {
    let mut out = String::new();
    let mut link_url: Option<String> = None;
    let mut link_text = String::new();
    let mut in_link = false;

    // Trim trailing cell separators before a row break.
    fn end_row(out: &mut String) {
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }

    for ev in parser(md) {
        match ev {
            Event::Start(tag) => match tag {
                Tag::Link { dest_url, .. } => {
                    in_link = true;
                    link_url = Some(dest_url.to_string());
                    link_text.clear();
                }
                Tag::Item => out.push_str("- "),
                _ => {}
            },
            Event::End(tag) => match tag {
                TagEnd::Heading(_) | TagEnd::Paragraph | TagEnd::BlockQuote(..) => out.push_str("\n\n"),
                TagEnd::Table => out.push('\n'),
                TagEnd::Item => out.push('\n'),
                TagEnd::TableRow | TagEnd::TableHead => end_row(&mut out),
                TagEnd::TableCell => out.push_str("  "),
                TagEnd::List(_) => out.push('\n'),
                TagEnd::Link => {
                    in_link = false;
                    let url = link_url.take().unwrap_or_default();
                    // "text (url)" - except when the text already is the url
                    // (paste-links) or a mailto of itself.
                    if link_text == url || format!("mailto:{}", link_text) == url {
                        out.push_str(&link_text);
                    } else {
                        out.push_str(&format!("{} ({})", link_text, url));
                    }
                }
                _ => {}
            },
            Event::Text(t) | Event::Code(t) => {
                if in_link {
                    link_text.push_str(&t);
                } else {
                    out.push_str(&t);
                }
            }
            Event::SoftBreak => out.push(' '),
            Event::HardBreak => out.push('\n'),
            Event::Rule => out.push_str("---\n\n"),
            Event::Html(t) | Event::InlineHtml(t) => out.push_str(&t),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_and_paragraph() {
        let r = render("# Hello\n\nWorld **bold**.\n", None);
        assert!(r.html.contains("<h1 style=\"margin:0 0 22px"));
        assert!(r.html.contains("<strong>bold</strong>"));
        assert!(r.text.starts_with("Hello\n\nWorld bold.\n"));
    }

    #[test]
    fn empty_header_table_is_borderless() {
        let md = "|  |  |\n| --- | ---: |\n| Subtotal | $5.00 |\n";
        let r = render(md, None);
        assert!(!r.html.contains("<thead>"), "empty header must be dropped: {}", r.html);
        assert!(r.html.contains("text-align:right;"));
        assert!(r.text.contains("Subtotal  $5.00"));
    }

    #[test]
    fn real_header_table_keeps_head() {
        let md = "| A | B |\n| --- | --- |\n| 1 | 2 |\n";
        let r = render(md, None);
        assert!(r.html.contains("<thead>"));
        assert!(r.html.contains("<th"));
    }

    #[test]
    fn shortcodes() {
        let r = render("# Hi\n\n{{code:123456}}\n\nBye.\n\n{{button:Go|https://x.example/y}}\n", None);
        assert!(r.html.contains("letter-spacing:10px"));
        assert!(r.html.contains(">123456</div>"));
        assert!(r.html.contains(">Go</a>"));
        assert!(r.html.contains("Or paste this into your browser"));
        assert!(r.text.contains("    123456"));
        assert!(r.text.contains("Go:\nhttps://x.example/y"));
    }

    #[test]
    fn raw_html_is_neutralized() {
        let r = render("Hello <script>alert(1)</script> there.\n", None);
        assert!(!r.html.contains("<script>"));
        assert!(r.html.contains("&lt;script&gt;"));
    }

    #[test]
    fn logo_chrome() {
        let r = render("# X\n", Some(("shop-logo", "LP-Research")));
        assert!(r.html.contains("cid:shop-logo"));
        assert!(r.html.contains("height:72px"));
        let r2 = render("# X\n", None);
        assert!(!r2.html.contains("cid:"));
    }

    #[test]
    fn escape_protects_structure() {
        let v = escape("a|b *c* [d]");
        let md = format!("|  |  |\n| --- | --- |\n| K | {} |\n", v);
        let r = render(&md, None);
        assert!(r.html.contains("a|b *c* [d]"));
    }

    #[test]
    fn hard_breaks_and_links() {
        let r = render("line one\\\nline two\n\n[label](https://a.example) and [https://b.example](https://b.example)\n", None);
        assert!(r.html.contains("line one<br>line two"));
        assert!(r.text.contains("line one\nline two"));
        assert!(r.text.contains("label (https://a.example)"));
        assert!(r.text.contains("https://b.example"));
        assert!(!r.text.contains("https://b.example (https://b.example)"));
    }

    #[test]
    fn blockquote_is_callout() {
        let r = render("> Thank you!\n", None);
        assert!(r.html.contains("border-left:3px solid #2563eb"));
        assert!(r.text.contains("Thank you!"));
    }

    #[test]
    fn template_substitution_and_line_drop() {
        let t = "# Hello {name}\n\nQuestions? Reach us at [{support}](mailto:{support}).\n\n{tracking_button}\n\nBye {unknown}.\n";
        let vars = vec![
            ("name", "Taro".to_string()),
            ("support", String::new()),
            ("tracking_button", "{{button:Track|https://x.example}}".to_string()),
        ];
        let r = apply_template(t, &vars);
        assert!(r.contains("# Hello Taro"));
        assert!(!r.contains("Questions?"), "empty-var line must be dropped: {}", r);
        assert!(r.contains("{{button:Track|https://x.example}}"));
        assert!(r.contains("Bye {unknown}."), "unknown tokens stay literal");
    }

    #[test]
    fn template_shortcode_with_variable_argument() {
        let t = "{{button:Track shipment|{url}}}\n";
        let r = apply_template(t, &[("url", "https://t.example/1".to_string())]);
        assert!(r.contains("{{button:Track shipment|https://t.example/1}}"), "{}", r);
        // Empty url drops the whole button line.
        let r = apply_template(t, &[("url", String::new())]);
        assert_eq!(r.trim(), "");
    }

    /// Writes a representative order confirmation to the temp dir for visual
    /// inspection (same convention as invoice_pdf::render_sample_invoice).
    #[test]
    fn render_sample_confirmation() {
        let md = "# Thank you for your order\n\n\
            Order #16 · 2026-08-28\n\n\
            Hi Taro Test,\n\n\
            Thanks for your purchase from LP-Research - we've received your order and are getting it ready.\n\n\
            > Thank you for supporting our sensors - your order helps us build the next generation.\n\n\
            ## Items\n\n\
            |  |  |\n| --- | ---: |\n\
            | 1 × LPMS-B2 — Wireless 9-Axis IMU (Bluetooth) | ¥63,800 |\n\n\
            |  |  |\n| --- | ---: |\n\
            | Subtotal | ¥58,000 |\n| Shipping | ¥1,500 |\n| Tax | ¥5,950 |\n| **Total** | **¥65,450** |\n\n\
            ## Ship to\n\nTaro Test\\\n3-10-4 Motoazabu\\\nRE-FLAT 201\\\nMinato-ku, 106-0046\\\nJP\n\n\
            ## Bill to\n\nTaro Test\\\n3-10-4 Motoazabu\\\nMinato-ku, 106-0046\\\nJP\n\n\
            A PDF invoice is attached to this email for your records.\n\n\
            We're processing your order now. You'll get a second email with your tracking number once it ships.\n\n\
            Questions? Reach us at [info@lp-research.com](mailto:info@lp-research.com).\n\n\
            \\- The LP-Research team\n";
        let r = render(md, Some(("shop-logo", "LP-Research")));
        let dir = std::env::temp_dir();
        std::fs::write(dir.join("sample-confirmation.html"), &r.html).unwrap();
        std::fs::write(dir.join("sample-confirmation.txt"), &r.text).unwrap();
        assert!(r.html.contains("<h1"));
        assert!(!r.html.contains("**"), "bold markers must be rendered, not literal");
    }
}
