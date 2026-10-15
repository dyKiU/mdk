use cgka_traits::GroupId;
use cgka_traits::convergence_pass::DurableConvergencePass;
use cgka_traits::storage::ConvergencePassStorage;

use crate::{AppError, MarmotApp};

impl MarmotApp {
    /// Inspect the durable pass without advancing the engine or its scheduler.
    /// Relay tests use this to witness retained input before exercising a send.
    #[doc(hidden)]
    pub fn convergence_pass_for_test(
        &self,
        label: &str,
        group_id: &GroupId,
    ) -> Result<Option<DurableConvergencePass>, AppError> {
        Ok(self.account_storage(label)?.convergence_pass(group_id)?)
    }
}

#[cfg(test)]
pub(crate) mod linking_cost {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    #[derive(Clone, Copy)]
    pub(crate) enum Site {
        ObservationRoster,
        ObservationHandoff,
        SiblingParent,
        BeginSibling,
    }

    #[derive(Default)]
    struct Trace {
        generation: u64,
        origin: Option<Instant>,
        cpu_origin: Option<u64>,
        active: bool,
        // Per site: calls, inclusive wall ns, inclusive scheduled CPU ns,
        // unavailable CPU observations, maximum wall ns. Nested sites overlap.
        counters: [[u64; 5]; 4],
    }

    fn trace() -> &'static Mutex<Trace> {
        static TRACE: OnceLock<Mutex<Trace>> = OnceLock::new();
        TRACE.get_or_init(|| Mutex::new(Trace::default()))
    }

    fn cpu_ns() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .ok()?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        }
        #[cfg(not(target_os = "linux"))]
        None
    }

    pub(crate) fn begin_fourth_completion() {
        let mut state = trace().lock().expect("linking cost trace");
        state.generation += 1;
        state.origin = Some(Instant::now());
        state.cpu_origin = cpu_ns();
        state.active = true;
        state.counters = [[0; 5]; 4];
        eprintln!("linking-cost phase=fourth-device-completion-start");
    }

    pub(crate) struct Span {
        site: Site,
        generation: u64,
        origin: Instant,
        cpu_origin: Option<u64>,
    }

    pub(crate) fn enter(site: Site) -> Option<Span> {
        let state = trace().lock().expect("linking cost trace");
        state.active.then(|| Span {
            site,
            generation: state.generation,
            origin: Instant::now(),
            cpu_origin: cpu_ns(),
        })
    }

    impl Drop for Span {
        fn drop(&mut self) {
            let wall_ns = self.origin.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let cpu = self.cpu_origin.zip(cpu_ns()).and_then(|(start, end)| end.checked_sub(start));
            let mut state = trace().lock().expect("linking cost trace");
            if !state.active || state.generation != self.generation {
                return;
            }
            let counters = &mut state.counters[self.site as usize];
            counters[0] += 1;
            counters[1] += wall_ns;
            if let Some(cpu) = cpu {
                counters[2] += cpu;
            } else {
                counters[3] += 1;
            }
            counters[4] = counters[4].max(wall_ns);
        }
    }

    pub(crate) fn finish_fourth_completion() {
        let mut state = trace().lock().expect("linking cost trace");
        if !state.active {
            return;
        }
        state.active = false;
        let wall_ns = state.origin.expect("trace origin").elapsed().as_nanos();
        let cpu = state.cpu_origin.zip(cpu_ns()).and_then(|(start, end)| end.checked_sub(start));
        eprintln!(
            "linking-cost phase=fourth-device-completion-end wall_ns={wall_ns} cpu_ns={cpu:?} counters={:?}",
            state.counters
        );
    }
}
