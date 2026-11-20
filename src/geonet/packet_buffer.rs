// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 Fundació Privada Internet i Innovació Digital a Catalunya (i2CAT)

//! GeoNetworking packet buffers (ETSI TS 103 836-4-1 V2.2.1 (2026-04),
//! clauses 8.5 and 8.6).
//!
//! [`PacketBuffer`] implements the maintenance rules shared by the Location
//! Service packet buffer (clause 8.5.3) and the UC/BC forwarding packet
//! buffers (clause 8.6.3):
//!
//! 1. packets are queued at the tail;
//! 2. on overflow, packets are removed from the head (head drop);
//! 3. a flush returns the stored packets in FIFO order;
//! 4. packets whose queuing time exceeds their lifetime are discarded;
//! 5. a flushed packet carries its lifetime reduced by the queuing time.
//!
//! [`CbfPacketBuffer`] is the CBF packet buffer (clause 8.6.3), in which every
//! packet is associated with a timer, as set by the CBF algorithms of clauses
//! E.3 and F.3.
//!
//! Both buffers are clock-agnostic: all operations take the current time in
//! milliseconds.
//!
//! Mirrors `flexstack/geonet/packet_buffer.py`.

use std::collections::VecDeque;

struct Entry<T> {
    item: T,
    size: usize,
    lifetime_ms: u64,
    enqueued_ms: u64,
    deadline_ms: u64,
}

impl<T> Entry<T> {
    /// Lifetime left after the queuing time (0 when expired).
    fn remaining_lifetime_ms(&self, now_ms: u64) -> u64 {
        (self.enqueued_ms + self.lifetime_ms).saturating_sub(now_ms)
    }
}

/// FIFO packet buffer with head drop and lifetime expiry (clauses 8.5.3, 8.6.3).
pub struct PacketBuffer<T> {
    capacity: usize,
    entries: VecDeque<Entry<T>>,
    size: usize,
}

impl<T> PacketBuffer<T> {
    /// Buffer of `capacity` octets.
    pub fn new(capacity: usize) -> Self {
        PacketBuffer {
            capacity,
            entries: VecDeque::new(),
            size: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Octets currently stored.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Queue a packet at the tail; remove packets from the head while the
    /// capacity is exceeded. Returns the number of packets dropped (a packet
    /// larger than the whole buffer drops itself).
    pub fn push(&mut self, item: T, size: usize, lifetime_ms: u64, now_ms: u64) -> usize {
        self.entries.push_back(Entry {
            item,
            size,
            lifetime_ms,
            enqueued_ms: now_ms,
            deadline_ms: 0,
        });
        self.size += size;
        let mut dropped = 0;
        while self.size > self.capacity {
            match self.entries.pop_front() {
                Some(e) => {
                    self.size -= e.size;
                    dropped += 1;
                }
                None => break,
            }
        }
        dropped
    }

    /// Discard the packets whose queuing time reached their lifetime.
    pub fn purge(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        let mut size = 0;
        self.entries.retain(|e| {
            let keep = e.remaining_lifetime_ms(now_ms) > 0;
            if keep {
                size += e.size;
            }
            keep
        });
        self.size = size;
        before - self.entries.len()
    }

    /// Empty the buffer, returning `(packet, remaining lifetime in ms)` in
    /// FIFO order; expired packets are discarded.
    pub fn flush(&mut self, now_ms: u64) -> Vec<(T, u64)> {
        self.size = 0;
        self.entries
            .drain(..)
            .filter_map(|e| {
                let remaining = e.remaining_lifetime_ms(now_ms);
                (remaining > 0).then_some((e.item, remaining))
            })
            .collect()
    }

    /// Discard every stored packet.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.size = 0;
    }
}

/// CBF packet buffer (clause 8.6.3): packets keyed by their identifier
/// (source GN_ADDR, sequence number), each with its own CBF timer.
pub struct CbfPacketBuffer<K: PartialEq + Clone, T> {
    capacity: usize,
    entries: VecDeque<(K, Entry<T>)>,
    size: usize,
}

impl<K: PartialEq + Clone, T> CbfPacketBuffer<K, T> {
    /// Buffer of `capacity` octets.
    pub fn new(capacity: usize) -> Self {
        CbfPacketBuffer {
            capacity,
            entries: VecDeque::new(),
            size: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, key: &K) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// The buffered packet of `key`, if any.
    pub fn get(&self, key: &K) -> Option<&T> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, e)| &e.item)
    }

    /// Buffer a packet and start its timer; head drop on overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        key: K,
        item: T,
        size: usize,
        lifetime_ms: u64,
        now_ms: u64,
        timeout_ms: f64,
    ) -> usize {
        self.remove(&key);
        self.entries.push_back((
            key,
            Entry {
                item,
                size,
                lifetime_ms,
                enqueued_ms: now_ms,
                deadline_ms: now_ms + timeout_ms.max(0.0).ceil() as u64,
            },
        ));
        self.size += size;
        let mut dropped = 0;
        while self.size > self.capacity {
            match self.entries.pop_front() {
                Some((_, e)) => {
                    self.size -= e.size;
                    dropped += 1;
                }
                None => break,
            }
        }
        dropped
    }

    /// Stop the timer of a packet and remove it from the buffer.
    pub fn remove(&mut self, key: &K) -> Option<T> {
        let index = self.entries.iter().position(|(k, _)| k == key)?;
        let (_, entry) = self.entries.remove(index)?;
        self.size -= entry.size;
        Some(entry.item)
    }

    /// Time left until the timer of `key` expires.
    pub fn remaining_timeout_ms(&self, key: &K, now_ms: u64) -> Option<u64> {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, e)| e.deadline_ms.saturating_sub(now_ms))
    }

    /// Restart the timer of a buffered packet.
    pub fn restart(&mut self, key: &K, now_ms: u64, timeout_ms: f64) {
        if let Some((_, e)) = self.entries.iter_mut().find(|(k, _)| k == key) {
            e.deadline_ms = now_ms + timeout_ms.max(0.0).ceil() as u64;
        }
    }

    /// Earliest timer expiry, in ms, or None when the buffer is empty.
    pub fn next_deadline(&self) -> Option<u64> {
        self.entries.iter().map(|(_, e)| e.deadline_ms).min()
    }

    /// Remove the packets whose timer expired, returning `(key, packet,
    /// remaining lifetime in ms)` in queue order; packets whose lifetime ran
    /// out while buffered are discarded.
    pub fn pop_expired(&mut self, now_ms: u64) -> Vec<(K, T, u64)> {
        let mut out = Vec::new();
        let mut kept = VecDeque::new();
        for (key, entry) in self.entries.drain(..) {
            if entry.deadline_ms <= now_ms {
                self.size -= entry.size;
                let remaining = entry.remaining_lifetime_ms(now_ms);
                if remaining > 0 {
                    out.push((key, entry.item, remaining));
                }
            } else {
                kept.push_back((key, entry));
            }
        }
        self.entries = kept;
        out
    }
}

/// Segment-based CBF timeout TO_CBF (equations E.1 to E.3, and F.1, F.2).
///
/// `distance_m` is the forwarding progress PROG (non-area CBF, clause E.3.2)
/// or the forwarding distance F_DIST (area CBF, clause F.3.2); `to_acc` is
/// the optional Access Layer constraint TO_ACC.
///
/// SEGN = max(1, ceil(D / DIST_MAX));
/// TO_CBF_WO_ACC = TO_CBF_MAX * SEGN + (TO_CBF_MIN - TO_CBF_MAX) / DIST_MAX
/// * (D - DIST_MAX * (SEGN - 1)); TO_CBF = max(TO_CBF_WO_ACC, TO_ACC).
pub fn cbf_timeout_ms(
    distance_m: f64,
    to_cbf_min: f64,
    to_cbf_max: f64,
    dist_max: f64,
    to_acc: f64,
) -> f64 {
    let distance_m = distance_m.max(0.0);
    let segn = (distance_m / dist_max).ceil().max(1.0);
    let wo_acc = to_cbf_max * segn
        + (to_cbf_min - to_cbf_max) / dist_max * (distance_m - dist_max * (segn - 1.0));
    wo_acc.max(to_acc)
}

/// Recalculated timeout TO_CBF_UPDATE (equation E.4) on reception of a
/// forwarded copy from a sender that is not a better forwarder.
pub fn cbf_timeout_update_ms(to_cbf: f64, to_cbf_rp: f64, to_cbf_max: f64) -> f64 {
    if (to_cbf - to_cbf_rp).abs() < to_cbf_max {
        to_cbf.min(to_cbf_rp)
    } else {
        to_cbf.max(to_cbf_rp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TO_MIN: f64 = 1.0;
    const TO_MAX: f64 = 100.0;
    const DIST_MAX: f64 = 1000.0;

    #[test]
    fn fifo_flush_with_reduced_lifetime() {
        let mut buffer = PacketBuffer::new(100);
        buffer.push("a", 10, 1000, 0);
        buffer.push("b", 10, 1000, 100);
        assert_eq!(buffer.flush(300), vec![("a", 700), ("b", 800)]);
        assert!(buffer.is_empty());
        assert_eq!(buffer.size(), 0);
    }

    #[test]
    fn head_drop_on_overflow() {
        let mut buffer = PacketBuffer::new(25);
        buffer.push("a", 10, 1000, 0);
        buffer.push("b", 10, 1000, 0);
        assert_eq!(buffer.push("c", 10, 1000, 0), 1);
        let items: Vec<_> = buffer.flush(0).into_iter().map(|(i, _)| i).collect();
        assert_eq!(items, vec!["b", "c"]);
    }

    #[test]
    fn packet_larger_than_buffer_is_dropped() {
        let mut buffer = PacketBuffer::new(5);
        assert_eq!(buffer.push("a", 10, 1000, 0), 1);
        assert_eq!(buffer.len(), 0);
    }

    #[test]
    fn expired_packets_are_discarded() {
        let mut buffer = PacketBuffer::new(100);
        buffer.push("short", 10, 50, 0);
        buffer.push("long", 10, 5000, 0);
        assert_eq!(buffer.purge(50), 1);
        buffer.push("short2", 10, 50, 0);
        assert_eq!(buffer.flush(60), vec![("long", 4940)]);
    }

    #[test]
    fn cbf_timer_expiry_and_restart() {
        let mut buffer = CbfPacketBuffer::new(1000);
        buffer.insert(1u32, "p1", 10, 1000, 0, 50.0);
        buffer.insert(2u32, "p2", 10, 1000, 0, 80.0);
        assert_eq!(buffer.next_deadline(), Some(50));
        assert_eq!(buffer.remaining_timeout_ms(&1, 20), Some(30));
        buffer.restart(&1, 20, 100.0);
        assert_eq!(buffer.pop_expired(80), vec![(2, "p2", 920)]);
        assert!(buffer.contains(&1));
        assert_eq!(buffer.get(&1), Some(&"p1"));
        assert_eq!(buffer.remove(&1), Some("p1"));
        assert_eq!(buffer.next_deadline(), None);
    }

    #[test]
    fn cbf_head_drop_and_lifetime() {
        let mut buffer = CbfPacketBuffer::new(15);
        buffer.insert(1u32, "a", 10, 1000, 0, 10.0);
        buffer.insert(2u32, "b", 10, 5, 0, 10.0);
        assert!(!buffer.contains(&1));
        assert!(buffer.pop_expired(10).is_empty()); // lifetime ran out
    }

    #[test]
    fn cbf_timeout_example_values() {
        let to = |d: f64| cbf_timeout_ms(d, TO_MIN, TO_MAX, DIST_MAX, 0.0);
        assert!((to(DIST_MAX) - TO_MIN).abs() < 1e-9);
        assert!((to(0.0) - TO_MAX).abs() < 1e-9);
        assert!((to(2.0 * DIST_MAX) - (TO_MAX + TO_MIN)).abs() < 1e-9);
        assert!((to(2.0001 * DIST_MAX) - 3.0 * TO_MAX).abs() < 0.1);
        assert!((to(DIST_MAX / 2.0) - (TO_MIN + TO_MAX) / 2.0).abs() < 1e-9);
    }

    #[test]
    fn cbf_timeout_access_layer_constraint() {
        assert_eq!(
            cbf_timeout_ms(DIST_MAX, TO_MIN, TO_MAX, DIST_MAX, 40.0),
            40.0
        );
    }

    #[test]
    fn cbf_timeout_update() {
        assert_eq!(cbf_timeout_update_ms(30.0, 60.0, TO_MAX), 30.0);
        assert_eq!(cbf_timeout_update_ms(30.0, 150.0, TO_MAX), 150.0);
    }
}
