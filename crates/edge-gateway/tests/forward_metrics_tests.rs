use edge_gateway::forwarding::metrics::global_forward_metrics;

#[test]
fn metrics_increment() {
    let m = global_forward_metrics();
    m.on_open("p1");
    m.on_close("p1", "normal");
    m.add_bytes("p1", "in", 10);
    m.on_error("p1", "io_error");
    let rendered = m.render();
    assert!(rendered.contains("forward_stream_open_total"));
    assert!(rendered.contains("protocol=\"p1\""));
}
