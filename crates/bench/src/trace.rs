//! What the benchmark binaries trace.
//!
//! - The hierarchical trace tree `--tracing` prints, with each span's heap.
//! - The prover's stage times: how long each direct child of a root span ran.

use crate::heap::{self, ClosedWindow, Heap, HeapWindow};
use crate::{pretty_bytes, pretty_f64, pretty_integer};
use std::cell::RefCell;
use std::fmt::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tracing::span::{Attributes, Id};
use tracing::{Level, Subscriber};
use tracing_forest::printer::Pretty;
use tracing_forest::tree::Tree;
use tracing_forest::util::LevelFilter;
use tracing_forest::{ForestLayer, Formatter, PrettyPrinter};
use tracing_subscriber::filter::{dynamic_filter_fn, filter_fn};
use tracing_subscriber::layer::{Context, Filter, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// A closed span's heap, with its closed children: the forest's tree again, spans only.
struct HeapNode {
    /// The span's window.
    window: ClosedWindow,
    /// The heaps of the spans opened inside it, in the order they closed.
    children: Vec<Self>,
}

/// An open span's window, and its children that closed.
struct OpenSpan {
    /// The window opened with the span.
    window: HeapWindow,
    /// The heaps of the spans that closed inside it.
    children: Vec<HeapNode>,
}

thread_local! {
    /// The root span that closed last on this thread, which the forest prints next.
    static CLOSED_ROOT: RefCell<Option<HeapNode>> = const { RefCell::new(None) };
}

/// Keeps each span's heap window, from when it is created to when it closes.
///
/// - Installed before the forest, so a root's heap is ready when the forest prints the root.
/// - Filtered as the forest is, so it sees the spans the forest sees.
struct HeapSpans;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for HeapSpans {
    fn on_new_span(&self, _: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("a new span is registered");
        span.extensions_mut().insert(OpenSpan {
            window: HeapWindow::open(),
            children: Vec::new(),
        });
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("a closing span is registered");
        let Some(open) = span.extensions_mut().remove::<OpenSpan>() else {
            return;
        };
        let node = HeapNode {
            window: open.window.close(),
            children: open.children,
        };
        match span.parent() {
            Some(parent) => {
                if let Some(parent) = parent.extensions_mut().get_mut::<OpenSpan>() {
                    parent.children.push(node);
                }
            }
            None => CLOSED_ROOT.with_borrow_mut(|root| *root = Some(node)),
        }
    }
}

/// What a span's line shows after its time.
#[derive(Clone, Copy, Debug)]
struct Line {
    /// The span's share of its parent's time, in percent.
    percentage: f64,
    /// Its heap above the bytes live when the root opened, when the counting allocator is the global one.
    heap: Option<Heap>,
}

/// Renders a root span's tree, with parent-relative percentages and each span's heap.
fn format_trace_tree(tree: &Tree) -> Result<String, Error> {
    let rendered = Pretty.fmt(tree)?;
    // The root's heap, kept only where the counting allocator saw the allocations.
    let heap = CLOSED_ROOT.take().filter(|_| heap::counting());
    let mut lines = Vec::new();
    collect_lines(
        tree,
        heap.as_ref(),
        heap.as_ref().map_or(0, |root| root.window.opened),
        None,
        &mut lines,
    );
    Ok(rewrite_trace_lines(&rendered, &lines))
}

/// Pushes one line per span of `tree`, depth first, as the forest prints them.
fn collect_lines(
    tree: &Tree,
    heap: Option<&HeapNode>,
    root_opened: isize,
    parent_duration: Option<Duration>,
    lines: &mut Vec<Line>,
) {
    let Tree::Span(span) = tree else {
        return;
    };

    let percentage = match parent_duration {
        None => 100.0,
        Some(duration) if duration.is_zero() => 0.0,
        Some(duration) => 100.0 * span.total_duration().as_nanos() as f64 / duration.as_nanos() as f64,
    };
    lines.push(Line {
        percentage,
        heap: heap.map(|node| node.window.heap_above(root_opened)),
    });

    let mut children = heap.map(|node| node.children.iter());
    for node in span.nodes() {
        let child = match node {
            Tree::Span(_) => children.as_mut().and_then(Iterator::next),
            Tree::Event(_) => None,
        };
        collect_lines(node, child, root_opened, Some(span.total_duration()), lines);
    }
}

/// Replaces the forest's root-relative percentages with parent-relative ones, followed by each span's heap.
///
/// The forest's optional self percentage goes too.
fn rewrite_trace_lines(rendered: &str, lines: &[Line]) -> String {
    let mut output = String::with_capacity(rendered.len());
    let mut lines = lines.iter();

    for segment in rendered.split_inclusive('\n') {
        let (line, newline) = segment.strip_suffix('\n').map_or((segment, ""), |line| (line, "\n"));

        let timing = line.find(" | ").and_then(|separator| {
            let value_start = separator + " | ".len();
            let values = &line[value_start..];
            let percent_end = values.find("% ]")?;
            let displayed = &values[..percent_end];
            let displayed_total = displayed.rsplit("% / ").next()?;

            displayed_total
                .parse::<f64>()
                .ok()
                .map(|_| (value_start, value_start + percent_end))
        });

        if let Some((value_start, percent_end)) = timing {
            let shown = lines
                .next()
                .expect("trace formatter found more spans than trace-tree timings");
            output.push_str(&line[..value_start]);
            output.push_str(&pretty_f64(shown.percentage));
            output.push('%');
            if let Some(heap) = shown.heap {
                output.push_str(&format!(
                    " | heap {} | {} allocs",
                    pretty_bytes(heap.peak),
                    pretty_integer(&heap.allocations)
                ));
            }
            output.push_str(&line[percent_end + 1..]);
        } else {
            output.push_str(line);
        }
        output.push_str(newline);
    }

    assert!(
        lines.next().is_none(),
        "trace formatter found fewer spans than trace-tree timings"
    );
    output
}

/// How many suppression guards are alive; the trace tree records only while none is.
static SUPPRESSED: AtomicUsize = AtomicUsize::new(0);

/// Suppresses trace-tree output until the returned guard is dropped.
///
/// A benchmark runs its pass several times, and only the final measured one should print a tree.
///
/// - Guards nest: output resumes when the last one is dropped.
/// - A span created while suppressed is never recorded, so it cannot reappear inside a later tree.
#[must_use = "tracing resumes as soon as the guard is dropped"]
pub fn suppress_tracing() -> TraceSuppressed {
    SUPPRESSED.fetch_add(1, Ordering::Relaxed);
    TraceSuppressed(())
}

/// A live suppression of the trace tree, lifted when dropped.
pub struct TraceSuppressed(());

impl Drop for TraceSuppressed {
    fn drop(&mut self) {
        SUPPRESSED.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The trace tree's filter: everything but what a suppression guard covers.
///
/// It is dynamic, never cached per callsite, so one callsite is recorded on one pass and skipped on the next.
fn recorded<S: Subscriber>() -> impl Filter<S> {
    dynamic_filter_fn(|_, _| SUPPRESSED.load(Ordering::Relaxed) == 0)
}

/// Installs the hierarchical tracing subscriber of the benchmark binaries.
///
/// - The default level is `INFO`, which `RUST_LOG` overrides.
/// - A subscriber already installed stays, so repeated calls do nothing.
/// - It also times the prover's stages, on every pass.
pub fn init_tracing() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let forest = ForestLayer::from(PrettyPrinter::new().formatter(format_trace_tree)).with_filter(recorded());

    let _ = Registry::default()
        .with(env_filter)
        .with(HeapSpans.with_filter(recorded()))
        .with(forest)
        .with(Stages)
        .try_init();
}

/// Installs the trace tree when `BENCH_TRACING` is set: the `benches/` targets' counterpart of `--tracing`.
pub fn init_tracing_from_env() {
    if std::env::var_os("BENCH_TRACING").is_some() {
        init_tracing();
    }
}

/// One stage of a proof: a direct child of the root span, and how long it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stage {
    /// The span's name.
    pub name: &'static str,
    /// From when the span was created to when it closed.
    pub elapsed: Duration,
}

/// The root span's name, whose children are the stages.
static ROOT: OnceLock<&'static str> = OnceLock::new();

/// The stages that closed since they were last taken.
static STAGES: Mutex<Vec<Stage>> = Mutex::new(Vec::new());

/// When a stage opened, kept in its span's extensions.
struct Opened(Instant);

/// Times every span whose parent is the root span.
struct Stages;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Stages {
    fn on_new_span(&self, _: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        // No root is named until a benchmark asks for its stages.
        let Some(&root) = ROOT.get() else { return };
        let span = ctx.span(id).expect("a new span is registered");
        if span.parent().is_some_and(|parent| parent.name() == root) {
            span.extensions_mut().insert(Opened(Instant::now()));
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let span = ctx.span(&id).expect("a closing span is registered");
        if let Some(Opened(opened)) = span.extensions().get::<Opened>() {
            STAGES.lock().unwrap().push(Stage {
                name: span.name(),
                elapsed: opened.elapsed(),
            });
        }
    }
}

/// Times the stages of every span named `root`: its direct children, by name.
///
/// Installs a subscriber enabling `INFO` spans and no events, unless the trace tree's is installed already.
/// That one times the stages too.
///
/// # Panics
///
/// Panics when called twice: a process has one root span.
pub fn time_stages(root: &'static str) {
    ROOT.set(root).expect("one root span per process");
    let spans = filter_fn(|metadata| metadata.is_span() && *metadata.level() <= Level::INFO);
    let _ = Registry::default().with(Stages.with_filter(spans)).try_init();
}

/// The stages that closed since the last call, in the order they closed.
pub fn take_stages() -> Vec<Stage> {
    std::mem::take(&mut STAGES.lock().unwrap())
}

#[cfg(test)]
mod tests {
    use super::{Heap, Line, rewrite_trace_lines};

    #[test]
    fn trace_output_uses_parent_relative_percentage() {
        let trace = concat!(
            "INFO     Prove [ 3.38s | 73.12% ]\n",
            "INFO     ┕━ PCS open [ 1.14s | 11.35% / 33.74% ]\n",
            "INFO        ┕━ Sumcheck round [ 17.6ms | 0.53% ] round: 0\n",
        );
        let line = |percentage| Line { percentage, heap: None };

        assert_eq!(
            rewrite_trace_lines(trace, &[line(100.0), line(33.727_810), line(1.543_860)]),
            concat!(
                "INFO     Prove [ 3.38s | 100% ]\n",
                "INFO     ┕━ PCS open [ 1.14s | 33.728% ]\n",
                "INFO        ┕━ Sumcheck round [ 17.6ms | 1.544% ] round: 0\n",
            )
        );
    }

    #[test]
    fn trace_output_shows_each_span_heap_after_its_percentage() {
        let trace = concat!(
            "INFO     Prove [ 3.38s | 73.12% ]\n",
            "INFO     ┕━ PCS open [ 1.14s | 11.35% / 33.74% ] round: 0\n",
        );
        let lines = [
            Line {
                percentage: 100.0,
                heap: Some(Heap {
                    peak: 3 << 29,
                    allocations: 12_345,
                }),
            },
            Line {
                percentage: 33.727_810,
                heap: Some(Heap {
                    peak: 1536,
                    allocations: 7,
                }),
            },
        ];

        assert_eq!(
            rewrite_trace_lines(trace, &lines),
            concat!(
                "INFO     Prove [ 3.38s | 100% | heap 1.5 GiB | 12,345 allocs ]\n",
                "INFO     ┕━ PCS open [ 1.14s | 33.728% | heap 1.5 KiB | 7 allocs ] round: 0\n",
            )
        );
    }
}
