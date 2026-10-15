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

// Diagnostic-only fourth-window actor boundaries; never product telemetry.
#[cfg(all(test, feature = "experimental-device-sync"))]
pub(crate) mod linking_boundary {
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Site {
        WorkerCommand,
        WorkerReceive,
        WorkerLinking,
        MaintainLinking,
        SiblingMaintenance,
        SiblingPrelude,
        BeginCompletedSibling,
        SiblingAdvance,
        AutomaticMaintenance,
        AutomaticPolicyCurrent,
        ChildAdmitted,
        HandshakeStarted,
        ProofStarted,
        HandshakeAck,
        ProofAck,
        HandshakeHarvested,
        ProofHarvested,
        PeerConsentApplied,
        PeerProofApplied,
    }
    const SITES: [Site; 19] = [
        Site::WorkerCommand, Site::WorkerReceive, Site::WorkerLinking,
        Site::MaintainLinking, Site::SiblingMaintenance, Site::SiblingPrelude,
        Site::BeginCompletedSibling, Site::SiblingAdvance,
        Site::AutomaticMaintenance, Site::AutomaticPolicyCurrent, Site::ChildAdmitted,
        Site::HandshakeStarted,
        Site::ProofStarted,
        Site::HandshakeAck,
        Site::ProofAck,
        Site::HandshakeHarvested,
        Site::ProofHarvested,
        Site::PeerConsentApplied,
        Site::PeerProofApplied,

    ];
    #[derive(Default)]
    struct Trace {
        active: bool,
        origin: Option<Instant>,
        cpu_origin: Option<u64>,
        // Private in-process client addresses are used only as opaque map keys.
        // Neither these keys nor account/device identifiers are ever exported.
        actors: Vec<usize>,
        omitted: u64,
        // entered, exited, last enter/end ns, inclusive total/max wall ns.
        rows: [[[u64; 6]; 19]; 8],
    }
    fn trace() -> &'static Mutex<Trace> {
        static TRACE: OnceLock<Mutex<Trace>> = OnceLock::new();
        TRACE.get_or_init(|| Mutex::new(Trace::default()))
    }
    fn cpu_ns() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/thread-self/schedstat")
                .ok()?.split_whitespace().next()?.parse().ok()
        }
        #[cfg(not(target_os = "linux"))]
        None
    }
    pub(crate) struct Phase;
    pub(crate) fn begin() -> Option<Phase> {
        if std::env::var("WN_BOUNDARY_PROBE").as_deref() != Ok("1") {
            return None;
        }
        let mut trace = trace().lock().expect("boundary trace");
        *trace = Trace { active: true, origin: Some(Instant::now()), cpu_origin: cpu_ns(), ..Trace::default() };
        eprintln!("linking-boundary phase=fourth-start");
        Some(Phase)
    }
    pub(crate) struct Span {
        actor: usize,
        site: Site,
        origin: Instant,
    }
    pub(crate) fn enter(actor_key: usize, site: Site) -> Option<Span> {
        let mut trace = trace().lock().expect("boundary trace");
        if !trace.active {
            return None;
        }
        let actor = match trace.actors.iter().position(|key| *key == actor_key) {
            Some(actor) => actor,
            None if trace.actors.len() < 8 => {
                trace.actors.push(actor_key);
                trace.actors.len() - 1
            }
            None => {
                trace.omitted += 1;
                return None;
            }
        };
        let elapsed = trace.origin.expect("boundary origin").elapsed().as_nanos() as u64;
        let row = &mut trace.rows[actor][site as usize];
        row[0] += 1;
        row[2] = elapsed;
        Some(Span { actor, site, origin: Instant::now() })
    }
    impl Drop for Span {
        fn drop(&mut self) {
            let mut trace = trace().lock().expect("boundary trace");
            if !trace.active {
                return;
            }
            let elapsed = trace.origin.expect("boundary origin").elapsed().as_nanos() as u64;
            let wall = self.origin.elapsed().as_nanos() as u64;
            let row = &mut trace.rows[self.actor][self.site as usize];
            row[1] += 1;
            row[3] = elapsed;
            row[4] += wall;
            row[5] = row[5].max(wall);
        }
    }
    impl Drop for Phase {
        fn drop(&mut self) {
            let mut trace = trace().lock().expect("boundary trace");
            trace.active = false;
            let wall_ns = trace.origin.expect("boundary origin").elapsed().as_nanos();
            let cpu_ns = trace.cpu_origin.zip(cpu_ns()).and_then(|(start, end)| end.checked_sub(start));
            eprintln!("linking-boundary phase=fourth-end wall_ns={wall_ns} cpu_ns={cpu_ns:?} omitted={}", trace.omitted);
            for actor in 0..trace.actors.len() {
                for site in SITES {
                    let values = trace.rows[actor][site as usize];
                    if values[0] != 0 {
                        eprintln!("linking-boundary actor={actor} site={site:?} values={values:?}");
                    }
                }
            }
        }
    }
}
