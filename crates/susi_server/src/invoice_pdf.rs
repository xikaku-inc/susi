// Local invoice PDF renderer.
//
// Rendered ourselves rather than reusing the PDF behind Stripe's
// `invoice_pdf` URL: that PDF is generated once when Stripe finalizes the
// invoice (status=open) and never refreshed even after the invoice
// transitions to paid, so it always shows a "Pay online" CTA and an
// "Amount due" line that don't make sense for a post-payment receipt.

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use printpdf::image_crate::{self, imageops::FilterType, GenericImageView, ImageFormat};
use printpdf::*;
use serde_json::Value;

const LOGO_PNG: &[u8] = include_bytes!("assets/xikaku-logo.png");
const LOGO_TARGET_WIDTH_MM: f32 = 28.0;

const COMPANY_NAME: &str = "Xikaku, Inc.";
const COMPANY_LINES: &[&str] = &[
    "4136 Del Rey Ave",
    "Marina Del Rey, California 90292",
    "United States",
    "+1 310-916-4636",
    "info@xikaku.com",
];

const PAGE_W: f32 = 215.9;
const PAGE_H: f32 = 279.4;
const LEFT: f32 = 18.0;
const RIGHT: f32 = PAGE_W - 18.0;

pub fn generate(
    event: &Value,
    line_items: &[Value],
    invoice: &Value,
    order_id: Option<i64>,
) -> Result<Vec<u8>> {
    let obj = event.pointer("/data/object").cloned().unwrap_or(Value::Null);
    let currency = obj.get("currency").and_then(|v| v.as_str()).unwrap_or("usd").to_uppercase();
    let amount_total    = obj.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_subtotal = obj.get("amount_subtotal").and_then(|v| v.as_i64()).unwrap_or(0);
    let td = obj.get("total_details").cloned().unwrap_or(Value::Null);
    let amount_shipping = td.get("amount_shipping").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_tax      = td.get("amount_tax").and_then(|v| v.as_i64()).unwrap_or(0);
    let amount_discount = td.get("amount_discount").and_then(|v| v.as_i64()).unwrap_or(0);

    let invoice_number = invoice
        .get("number").and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| order_id.map(|i| format!("XK-{:04}", i)).unwrap_or_else(|| "—".into()));

    let date = invoice.get("created").and_then(|v| v.as_i64())
        .or_else(|| obj.get("created").and_then(|v| v.as_i64()))
        .and_then(|t| Utc.timestamp_opt(t, 0).single())
        .unwrap_or_else(Utc::now);
    let date_str = date.format("%B %-d, %Y").to_string();

    let bill_to = address_block(obj.get("customer_details"), true);
    let ship_to = address_block(obj.get("shipping_details"), false);

    let (doc, page1, layer1) = PdfDocument::new(
        format!("Invoice {}", invoice_number),
        Mm(PAGE_W), Mm(PAGE_H),
        "Layer 1",
    );
    let l = doc.get_page(page1).get_layer(layer1);
    let bold    = doc.add_builtin_font(BuiltinFont::HelveticaBold).context("font")?;
    let regular = doc.add_builtin_font(BuiltinFont::Helvetica).context("font")?;

    let dark   = Color::Rgb(Rgb::new(0.10, 0.11, 0.14, None));
    let muted  = Color::Rgb(Rgb::new(0.36, 0.39, 0.44, None));
    let border = Color::Rgb(Rgb::new(0.84, 0.86, 0.89, None));

    // ---------- Header ----------
    l.set_fill_color(dark.clone());
    l.use_text("Invoice", 24.0, Mm(LEFT), Mm(263.0), &bold);
    if let Err(e) = draw_logo(&l, RIGHT, 261.0) {
        // Fall back to a text wordmark if the PNG decode ever fails.
        log::warn!("logo embed failed, falling back to text: {}", e);
        let cw = text_w(COMPANY_NAME, 14.0);
        l.use_text(COMPANY_NAME, 14.0, Mm(RIGHT - cw), Mm(266.0), &bold);
    }

    // ---------- Meta block ----------
    let meta = [
        ("Invoice number", invoice_number.as_str()),
        ("Date of issue",  date_str.as_str()),
        ("Date paid",      date_str.as_str()),
    ];
    let mut y: f32 = 250.0;
    for (k, v) in meta.iter() {
        l.set_fill_color(dark.clone());
        l.use_text(*k, 9.0, Mm(LEFT), Mm(y), &bold);
        l.use_text(*v, 9.0, Mm(LEFT + 32.0), Mm(y), &regular);
        y -= 4.5;
    }

    // ---------- From / Bill to / Ship to ----------
    let col_w = (RIGHT - LEFT) / 3.0;
    let col_y_top: f32 = 228.0;
    let col_x = [LEFT, LEFT + col_w, LEFT + 2.0 * col_w];

    let company: Vec<String> = COMPANY_LINES.iter().map(|s| s.to_string()).collect();
    draw_address_column(&l, &bold, &regular, &dark, &muted,
        col_x[0], col_y_top, COMPANY_NAME, &company);
    draw_address_column(&l, &bold, &regular, &dark, &muted,
        col_x[1], col_y_top, "Bill to", &bill_to);
    if !ship_to.is_empty() && ship_to != bill_to {
        draw_address_column(&l, &bold, &regular, &dark, &muted,
            col_x[2], col_y_top, "Ship to", &ship_to);
    }

    // ---------- Big total ----------
    let total_line = format!("{} {} paid on {}", fmt_money(amount_total), currency, date_str);
    l.set_fill_color(dark.clone());
    l.use_text(&total_line, 18.0, Mm(LEFT), Mm(178.0), &bold);

    // ---------- Items table ----------
    let table_top: f32 = 162.0;
    let row_h: f32 = 7.0;
    let col_qty: f32   = LEFT + 110.0;
    let col_unit: f32  = LEFT + 132.0;
    let col_amt_r: f32 = RIGHT;

    l.set_fill_color(muted.clone());
    l.use_text("Description", 9.0, Mm(LEFT), Mm(table_top), &bold);
    right_text(&l, &bold, "Qty",        9.0, col_qty + 12.0, table_top);
    right_text(&l, &bold, "Unit price", 9.0, col_unit + 22.0, table_top);
    right_text(&l, &bold, "Amount",     9.0, col_amt_r,       table_top);
    draw_hline(&l, &border, LEFT, RIGHT, table_top - 2.0, 0.4);

    let mut y: f32 = table_top - 2.0 - row_h;
    if line_items.is_empty() {
        l.set_fill_color(muted.clone());
        l.use_text("(no items)", 10.0, Mm(LEFT), Mm(y), &regular);
        y -= row_h;
    } else {
        for li in line_items {
            let qty  = li.get("quantity").and_then(|v| v.as_i64()).unwrap_or(1);
            let desc = li.get("description").and_then(|v| v.as_str()).unwrap_or("(item)").to_string();
            let amt  = li.get("amount_total").and_then(|v| v.as_i64()).unwrap_or(0);
            let unit = if qty > 0 { amt / qty } else { amt };
            l.set_fill_color(dark.clone());
            l.use_text(truncate(&desc, 60), 10.0, Mm(LEFT), Mm(y), &regular);
            right_text(&l, &regular, &qty.to_string(),       10.0, col_qty + 12.0, y);
            right_text(&l, &regular, &fmt_money(unit),       10.0, col_unit + 22.0, y);
            right_text(&l, &regular, &fmt_money(amt),        10.0, col_amt_r,       y);
            y -= row_h;
        }
    }
    draw_hline(&l, &border, LEFT, RIGHT, y + 2.5, 0.4);

    // ---------- Totals ----------
    let mut yt: f32 = y - 5.0;
    let label_x: f32 = RIGHT - 60.0;
    let totals: &[(&str, i64, bool)] = &[
        ("Subtotal", amount_subtotal,    true),
        ("Discount", -amount_discount,   amount_discount != 0),
        ("Shipping", amount_shipping,    true),
        ("Tax",      amount_tax,         amount_tax != 0),
    ];
    for (lbl, amt, show) in totals.iter() {
        if !*show { continue; }
        l.set_fill_color(muted.clone());
        l.use_text(*lbl, 10.0, Mm(label_x), Mm(yt), &regular);
        l.set_fill_color(dark.clone());
        right_text(&l, &regular, &fmt_money(*amt), 10.0, RIGHT, yt);
        yt -= 5.0;
    }
    draw_hline(&l, &border, label_x, RIGHT, yt + 2.5, 0.4);
    yt -= 1.5;
    l.set_fill_color(dark.clone());
    l.use_text("Total", 11.0, Mm(label_x), Mm(yt), &bold);
    right_text(&l, &bold, &format!("{} {}", fmt_money(amount_total), currency), 11.0, RIGHT, yt);

    // ---------- Serialize ----------
    let buf: Vec<u8> = Vec::new();
    let mut bw = std::io::BufWriter::new(buf);
    doc.save(&mut bw).context("pdf save")?;
    let bytes = bw.into_inner().context("pdf flush")?;
    Ok(bytes)
}

// Embed the Xikaku PNG with its top-right corner at (right_mm, top_mm).
// We resize the source down to the on-page pixel count first, because
// printpdf 0.7 stores images as raw uncompressed bytes — a 1200×402 RGBA
// source balloons the PDF to ~1.9 MB, while a 400×134 resize keeps it
// under 200 KB without visibly degrading the print at 28 mm wide.
fn draw_logo(layer: &PdfLayerReference, right_mm: f32, top_mm: f32) -> Result<()> {
    let img = image_crate::load_from_memory_with_format(LOGO_PNG, ImageFormat::Png)
        .context("png decode")?;
    // Target ~300 dpi at the on-page width.
    let target_w_px = (LOGO_TARGET_WIDTH_MM / 25.4 * 300.0).round() as u32;
    let (orig_w, orig_h) = img.dimensions();
    let target_h_px = (orig_h as f32 * target_w_px as f32 / orig_w as f32).round() as u32;
    let resized = img.resize(target_w_px, target_h_px, FilterType::Lanczos3);
    let drawn_w_mm = LOGO_TARGET_WIDTH_MM;
    let drawn_h_mm = orig_h as f32 * LOGO_TARGET_WIDTH_MM / orig_w as f32;
    let image = Image::from_dynamic_image(&resized);
    image.add_to_layer(layer.clone(), ImageTransform {
        translate_x: Some(Mm(right_mm - drawn_w_mm)),
        translate_y: Some(Mm(top_mm - drawn_h_mm)),
        dpi: Some(300.0),
        ..Default::default()
    });
    Ok(())
}

fn draw_address_column(
    l: &PdfLayerReference,
    bold: &IndirectFontRef,
    regular: &IndirectFontRef,
    dark: &Color,
    muted: &Color,
    x: f32, y_top: f32, header: &str, lines: &[String],
) {
    l.set_fill_color(muted.clone());
    l.use_text(header, 9.0, Mm(x), Mm(y_top), bold);
    l.set_fill_color(dark.clone());
    let mut y = y_top - 5.0;
    for s in lines {
        if s.is_empty() { continue; }
        l.use_text(truncate(s, 40), 9.0, Mm(x), Mm(y), regular);
        y -= 4.2;
    }
}

fn address_block(details: Option<&Value>, include_email: bool) -> Vec<String> {
    let Some(d) = details else { return Vec::new(); };
    let mut out = Vec::new();
    if let Some(name) = d.get("name").and_then(|v| v.as_str()) {
        if !name.is_empty() { out.push(name.to_string()); }
    }
    let addr = d.get("address").cloned().unwrap_or(Value::Null);
    let g = |k: &str| addr.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let line1 = g("line1");
    let line2 = g("line2");
    let city  = g("city");
    let state = g("state");
    let zip   = g("postal_code");
    let country = g("country");
    if !line1.is_empty() { out.push(line1); }
    if !line2.is_empty() { out.push(line2); }
    let mut csz = String::new();
    if !city.is_empty() { csz.push_str(&city); }
    if !state.is_empty() {
        if !csz.is_empty() { csz.push_str(", "); }
        csz.push_str(&state);
    }
    if !zip.is_empty() {
        if !csz.is_empty() { csz.push(' '); }
        csz.push_str(&zip);
    }
    if !csz.is_empty() { out.push(csz); }
    if !country.is_empty() { out.push(country); }
    if include_email {
        if let Some(e) = d.get("email").and_then(|v| v.as_str()) {
            if !e.is_empty() { out.push(e.to_string()); }
        }
    }
    out
}

fn fmt_money(cents: i64) -> String {
    let neg = cents < 0;
    let v = cents.unsigned_abs();
    let dollars = v / 100;
    let frac = v % 100;
    let mut s = String::new();
    if neg { s.push('-'); }
    s.push('$');
    s.push_str(&dollars.to_string());
    s.push('.');
    s.push_str(&format!("{:02}", frac));
    s
}

// Approximate Helvetica width in mm. PDF base-14 Helvetica is roughly
// 0.5 em wide on average; for our short labels and amounts that's enough
// to right-align without pulling in a full font-metrics table.
fn text_w(s: &str, size_pt: f32) -> f32 {
    s.chars().count() as f32 * size_pt * 0.50 * 0.3528
}

fn right_text(
    l: &PdfLayerReference,
    f: &IndirectFontRef,
    s: &str, size_pt: f32, x_right: f32, y: f32,
) {
    let w = text_w(s, size_pt);
    l.use_text(s, size_pt, Mm(x_right - w), Mm(y), f);
}

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars { return s.to_string(); }
    let mut out: String = s.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

fn draw_hline(l: &PdfLayerReference, color: &Color, x1: f32, x2: f32, y: f32, thickness: f32) {
    l.set_outline_color(color.clone());
    l.set_outline_thickness(thickness);
    let line = Line {
        points: vec![
            (Point::new(Mm(x1), Mm(y)), false),
            (Point::new(Mm(x2), Mm(y)), false),
        ],
        is_closed: false,
    };
    l.add_line(line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_sample_invoice() {
        let event = json!({
            "data": { "object": {
                "id": "cs_test_sample",
                "currency": "usd",
                "amount_total": 51400,
                "amount_subtotal": 49900,
                "total_details": { "amount_shipping": 1500, "amount_tax": 0, "amount_discount": 0 },
                "customer_details": {
                    "name": "Klaus Petersen",
                    "email": "klaus@xikaku.com",
                    "address": {
                        "line1": "4223 Glencoe Ave Suite C215",
                        "line2": "C215",
                        "city": "Marina del Rey",
                        "state": "California",
                        "postal_code": "90292",
                        "country": "United States",
                    },
                },
                "shipping_details": {
                    "name": "Klaus Petersen",
                    "address": {
                        "line1": "4223 Glencoe Ave Suite C215",
                        "line2": "C215",
                        "city": "Marina del Rey",
                        "state": "California",
                        "postal_code": "90292",
                        "country": "United States",
                    },
                },
            }}
        });
        let line_items = vec![
            json!({"quantity": 1, "description": "LPMS-NAV3-CAN — Industrial 6-Axis IMU (CAN)", "amount_total": 49900, "currency": "usd"}),
        ];
        let invoice = json!({"number": "9VRGWXU6-0001", "created": 1745625600i64});
        let bytes = generate(&event, &line_items, &invoice, Some(7)).expect("generate");
        let out = "C:/tmp/sample-invoice.pdf";
        std::fs::write(out, &bytes).unwrap();
        eprintln!("wrote {} ({} bytes)", out, bytes.len());
    }
}

