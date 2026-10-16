//! Test-only bounded observations; never protocol inputs.
use std::time::Instant;

pub(crate) struct PublicationProbe {
    origin: Instant,
    next: u64,
    rows: Vec<[u64; 14]>,
    overflow: u64,
    passes: [[u64; 4]; 2],
}
impl Default for PublicationProbe {
    fn default() -> Self {
        Self { origin: Instant::now(), next: 0, rows: Vec::new(), overflow: 0, passes: [[0; 4]; 2] }
    }
}
impl PublicationProbe {
    fn time(&self) -> u64 { self.origin.elapsed().as_millis() as u64 + 1 }
    pub(crate) fn schedule(&mut self, kind: u64) -> u64 {
        self.next += 1;
        if self.rows.len() < 32 {
            let mut row = [0; 14];
            row[0] = self.next; row[1] = kind; row[2] = self.time();
            self.rows.push(row);
        } else { self.overflow += 1; }
        self.next
    }
    pub(crate) fn event(&mut self, generation: u64, column: usize) {
        let time = self.time();
        if let Some(row) = self.rows.iter_mut().find(|row| row[0] == generation) {
            if row[column] == 0 { row[column] = time; }
        }
    }
    pub(crate) fn visit(&mut self, generation: u64, finished: bool, periodic: bool) {
        let time = self.time();
        if finished { self.event(generation, 10); }
        if let Some(row) = self.rows.iter_mut().find(|row| row[0] == generation) { row[11] = time; row[12] = u64::from(periodic); }
    }
    pub(crate) fn pass(&mut self, wake: bool, entry: bool, bits: u64) {
        let time = self.time();
        let row = &mut self.passes[usize::from(wake)];
        row[usize::from(!entry)] += 1; row[2] = time; row[3] = bits;
    }
    pub(crate) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"rows":self.rows,"scheduled":self.next,"overflow":self.overflow,"passes":self.passes,"at_ms":self.time()})
    }
}
