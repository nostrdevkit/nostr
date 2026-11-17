use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

// Net (live) allocations made by the current thread.
thread_local! {
    static LIVE_ALLOCATIONS: Cell<isize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let _ = LIVE_ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        let _ = LIVE_ALLOCATIONS.try_with(|c| c.set(c.get() - 1));
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_allocations() -> isize {
    LIVE_ALLOCATIONS.with(Cell::get)
}

pub(crate) fn allocation_delta<F, R>(f: F) -> (R, isize)
where
    F: FnOnce() -> R,
{
    let before = live_allocations();
    (f(), live_allocations() - before)
}
