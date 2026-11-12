use comfy_table::{
    Cell, CellAlignment, ContentArrangement, ContentLineStyle, LineStyle, Table, presets::UTF8_FULL,
};

use crate::model::{Report, TestOutcome};

fn styled_table() -> Table {
    let mut table = Table::new();
    table.load_style(
        UTF8_FULL
            .header_lines(ContentLineStyle::new('│', '│', '│'))
            .content_lines(ContentLineStyle::new('│', '│', '│'))
            .row_separator(LineStyle::new('├', '─', '┼', '┤')),
    );
    table
}

pub(crate) fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&"─".repeat(33));
    out.push('\n');
    out.push_str("\tBenchmark Report\n");
    out.push_str(&"─".repeat(33));

    out.push_str("\n\nCompiler\n");
    out.push_str(&format!("{}\n", compiler_table(report)));

    out.push_str("\nBenchmarks\n");
    out.push_str(&format!("{}\n", benchmark_table(report)));

    out.push_str("\nTests\n");
    out.push_str(&format!("{}\n", test_table(report)));

    if report
        .programs
        .iter()
        .any(|program| program.load_error.is_some())
    {
        out.push_str("\nLoad Errors\n");
        out.push_str(&format!("{}\n", load_error_table(report)));
    }

    out.push_str("\nSummary\n");
    out.push_str(&format!("{}\n", summary_table(report)));
    out.push('\n');
    out
}

fn compiler_table(report: &Report) -> Table {
    let mut table = styled_table();
    table
        .set_header(vec!["Toolchain", "Version"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    for (label, version) in &report.compiler {
        table.add_row(vec![Cell::new(label), Cell::new(version)]);
    }
    table
}

fn summary_table(report: &Report) -> Table {
    let (changed, unchanged) = report
        .programs
        .iter()
        .flat_map(|program| &program.benchmarks)
        .fold((0, 0), |(changed, unchanged), benchmark| {
            if benchmark.has_issue() {
                (changed + 1, unchanged)
            } else {
                (changed, unchanged + 1)
            }
        });
    let (passed, failed) = report
        .programs
        .iter()
        .flat_map(|program| &program.tests)
        .fold((0, 0), |(passed, failed), test| {
            if test.is_failed() {
                (passed, failed + 1)
            } else if test.outcome == TestOutcome::Passed {
                (passed + 1, failed)
            } else {
                (passed, failed)
            }
        });
    let mut table = styled_table();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.add_row(vec![
        Cell::new("Benchmarks"),
        Cell::new(format!("{unchanged} unchanged, {changed} changed")),
    ]);
    table.add_row(vec![
        Cell::new("Tests"),
        Cell::new(format!("{passed} passed, {failed} failed")),
    ]);
    table
}

fn benchmark_table(report: &Report) -> Table {
    let mut table = styled_table();
    table
        .set_header(vec![
            "Program",
            "Benchmark",
            "Expected CU",
            "Actual CU",
            "Delta",
            "Error",
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);
    for program in &report.programs {
        for benchmark in &program.benchmarks {
            let measured = benchmark.measured;
            table.add_row(vec![
                Cell::new(&program.name),
                Cell::new(&benchmark.name),
                Cell::new(benchmark.expected_compute_units).set_alignment(CellAlignment::Right),
                if measured {
                    Cell::new(benchmark.actual_compute_units).set_alignment(CellAlignment::Right)
                } else {
                    Cell::new("-").set_alignment(CellAlignment::Right)
                },
                if measured {
                    Cell::new(get_delta(benchmark.delta_compute_units))
                        .set_alignment(CellAlignment::Right)
                } else {
                    Cell::new("-").set_alignment(CellAlignment::Right)
                },
                Cell::new(benchmark.error.as_deref().unwrap_or("-")),
            ]);
        }
    }
    table
}

fn test_table(report: &Report) -> Table {
    let mut table = styled_table();
    table
        .set_header(vec!["Program", "Test", "Result", "Error"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    for program in &report.programs {
        for test in &program.tests {
            table.add_row(vec![
                Cell::new(&program.name),
                Cell::new(&test.name),
                Cell::new(test.outcome.label()),
                Cell::new(test.error.as_deref().unwrap_or("-")),
            ]);
        }
    }
    table
}

fn load_error_table(report: &Report) -> Table {
    let mut table = styled_table();
    table
        .set_header(vec!["Program", "Error"])
        .set_content_arrangement(ContentArrangement::Dynamic);
    for program in &report.programs {
        if let Some(error) = &program.load_error {
            table.add_row(vec![Cell::new(&program.name), Cell::new(error)]);
        }
    }
    table
}

fn get_delta(value: i64) -> String {
    if value > 0 {
        format!("+{value}")
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProgramReport;

    #[test]
    fn renders_load_errors() {
        let report = Report {
            compiler: Vec::new(),
            programs: vec![ProgramReport {
                name: "program".to_owned(),
                load_error: Some("bad elf".to_owned()),
                ..Default::default()
            }],
        };

        let rendered = render(&report);

        assert!(rendered.contains("Load Errors"));
        assert!(rendered.contains("bad elf"));
    }
}
