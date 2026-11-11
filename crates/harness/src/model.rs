use crate::RunOutcome;

pub(crate) struct Report {
    pub(crate) compiler: Vec<(String, String)>,
    pub(crate) programs: Vec<ProgramReport>,
}

#[derive(Debug, Default)]
pub(crate) struct BenchmarkReport {
    pub(crate) name: String,
    pub(crate) measured: bool,
    pub(crate) expected_compute_units: u64,
    pub(crate) actual_compute_units: u64,
    pub(crate) delta_compute_units: i64,
    pub(crate) error: Option<String>,
}

impl BenchmarkReport {
    pub(crate) fn has_failed(&self) -> bool {
        self.error.is_some()
    }

    pub(crate) fn has_changed(&self) -> bool {
        self.delta_compute_units != 0
    }

    pub(crate) fn has_issue(&self) -> bool {
        self.has_failed() || self.has_changed()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TestOutcome {
    Passed,
    Failed,
    Ignored,
}

impl TestOutcome {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Passed => "Pass",
            Self::Failed => "Failed",
            Self::Ignored => "Ignored",
        }
    }
}

#[derive(Debug)]
pub(crate) struct TestReport {
    pub(crate) name: String,
    pub(crate) outcome: TestOutcome,
    pub(crate) error: Option<String>,
}

impl TestReport {
    pub(crate) fn is_failed(&self) -> bool {
        self.outcome == TestOutcome::Failed
    }
}

#[derive(Default)]
pub(crate) struct ProgramReport {
    pub(crate) name: String,
    pub(crate) benchmarks: Vec<BenchmarkReport>,
    pub(crate) tests: Vec<TestReport>,
    pub(crate) load_error: Option<String>,
}

impl ProgramReport {
    /// Classifies the program's tests, benchmarks, and load status.
    pub(crate) fn outcome(&self) -> RunOutcome {
        if self.load_error.is_some()
            || self.tests.iter().any(TestReport::is_failed)
            || self.benchmarks.iter().any(BenchmarkReport::has_failed)
        {
            RunOutcome::Failure
        } else if self.benchmarks.iter().any(BenchmarkReport::has_changed) {
            RunOutcome::Issues
        } else {
            RunOutcome::Success
        }
    }
}
