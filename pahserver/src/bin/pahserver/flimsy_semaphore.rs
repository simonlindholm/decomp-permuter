use std::convert::TryInto;
use std::sync::atomic::{AtomicIsize, Ordering};

use tokio::sync::Notify;

/// An unfair semaphore that allows overdrafts.
pub struct FlimsySemaphore {
    notify: Notify,
    slots: AtomicIsize,
}

impl FlimsySemaphore {
    pub fn new(count: usize) -> FlimsySemaphore {
        FlimsySemaphore {
            notify: Notify::new(),
            slots: AtomicIsize::new(count.try_into().unwrap()),
        }
    }

    pub fn acquire_ignore_limit(&self) {
        self.slots.fetch_add(-1, Ordering::Acquire);
    }

    pub async fn acquire(&self) {
        let mut was_woken = false;
        let mut val = self.slots.load(Ordering::Relaxed);
        loop {
            if val > 0 {
                match self.slots.compare_exchange(val, val - 1, Ordering::AcqRel, Ordering::Relaxed) {
                    Ok(_) => {
                        if was_woken && val > 1 {
                            self.notify.notify_one();
                        }
                        return;
                    }
                    Err(actually) => {
                        val = actually;
                    }
                }
            } else {
                match self.slots.compare_exchange(val, val, Ordering::AcqRel, Ordering::Relaxed) {
                    Ok(_) => {
                        self.notify.notified().await;
                        was_woken = true;
                    }
                    Err(actually) => {
                        val = actually;
                    }
                }
            }
        }
    }

    pub fn release(&self) {
        if self.slots.fetch_add(1, Ordering::AcqRel) == 0 {
            self.notify.notify_one();
        }
    }
}
