use anyhow::Result;
use regex::Regex;

/// Fetch /metrics and extract counters for forward_errors_total (io_error*) and forward_stream_close_total (io_error).
pub async fn fetch_io_error_metrics(url: &str, protocol: &str) -> Result<(u64, u64)> {
    let body = reqwest::get(url).await?.text().await?;
    let re_err = Regex::new(&format!(
        r#"^forward_errors_total\{{[^}}]*protocol="{}"[^}}]*code="io_error[^"]*"\}} ([0-9]+\.?[0-9]*)"#,
        regex::escape(protocol)
    ))?;
    let re_close = Regex::new(&format!(
        r#"^forward_stream_close_total\{{[^}}]*protocol="{}"[^}}]*reason="io_error[^"]*"\}} ([0-9]+\.?[0-9]*)"#,
        regex::escape(protocol)
    ))?;

    let mut io_err = 0u64;
    let mut close_io = 0u64;

    for line in body.lines() {
        if let Some(caps) = re_err.captures(line) {
            if let Some(v) = caps.get(1) {
                io_err = v.as_str().parse::<f64>().unwrap_or(0.0) as u64;
            }
        }
        if let Some(caps) = re_close.captures(line) {
            if let Some(v) = caps.get(1) {
                close_io = v.as_str().parse::<f64>().unwrap_or(0.0) as u64;
            }
        }
    }

    Ok((io_err, close_io))
}
