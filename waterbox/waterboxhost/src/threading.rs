use crate::{syscall_defs::*, context::Context};
use std::sync::atomic::{Ordering, AtomicU32};
use std::{thread::JoinHandle, mem::transmute};
use parking_lot_core::*;

pub struct GuestThread {
	context: Context,
	NativeThread: JoinHandle<()>,
}

impl GuestThread {
	
}


const HOST_ABORTED: UnparkToken = UnparkToken(1);

// Mirror addresses are not used because of mprotect concerns (if it's not writable, we crash, whatever),
// but because parking_lot_core requires unique addresses to operate on

pub fn futex_wait(context: &mut Context, mirror_addr: usize, compare: u32) -> SyscallResult {
	let ret = unsafe {
		let atom = transmute::<_, &AtomicU32>(mirror_addr);
		let res = park(
			mirror_addr,
			|| {
				atom.load(Ordering::SeqCst) == compare
			},
			|| {
				context.park_addr = mirror_addr
			},
			|_, _| {},
			DEFAULT_PARK_TOKEN,
			None
		);
		match res {
			ParkResult::Invalid => {
				Err(EAGAIN)
			},
			ParkResult::Unparked(tok) if tok == DEFAULT_UNPARK_TOKEN => {
				Ok(())
			},
			ParkResult::Unparked(tok) if tok == HOST_ABORTED => {
				Err(E_WBX_HOSTABORT)
			},
			_ => panic!(),
		}
	};
	context.park_addr = 0;
	ret
}

pub fn futex_wake(mirror_addr: usize, count: u32) -> usize {
	let mut i = 0;
	unsafe {
		let res = unpark_filter(
			mirror_addr,
			|_| {
				if i < count {
					i += 1;
					FilterOp::Unpark
				} else {
					FilterOp::Stop
				}
			},
			|_| DEFAULT_UNPARK_TOKEN
		);
		res.unparked_threads
	}
}

pub fn futex_requeue(mirror_addr_from: usize, mirror_addr_to: usize, wake_count: u32, requeue_count: u32) -> Result<usize, SyscallError> {
	let op = match (wake_count, requeue_count) {
		(0, 0) => return Ok(0),
		// musl only hits this variant
		(0, 1) => RequeueOp::RequeueOne, 
		(0, 0x7fffffff) => RequeueOp::RequeueAll,
		(1, 0) => RequeueOp::UnparkOne,
		(1, 0x7fffffff) => RequeueOp::UnparkOneRequeueRest,
		// parking_lot_core doesn't support all of the possibilities, so ehhhh
		_ => return Err(EINVAL),
	};

	unsafe {
		let res = unpark_requeue(
			mirror_addr_from,
			mirror_addr_to,
			|| op,
			|_, _| DEFAULT_UNPARK_TOKEN
		);
		Ok(res.unparked_threads + res.requeued_threads)
	}
}

// don't handle priority inversion, or the clock information (how could we introduce a clock, anyway?)
// always handoff ("fair") to reduce nondeterminism
pub fn futex_lock_pi(context: &mut Context, mirror_addr: usize) -> SyscallResult {
	unsafe {
		let atom = transmute::<_, &AtomicU32>(mirror_addr);
		let ret = loop {
			let owner = atom.compare_exchange_weak(
				0, context.tid, Ordering::SeqCst, Ordering::SeqCst);
			let owner_tid = match owner {
				Ok(_) => return Ok(()),
				Err(v) => v
			};
			let res = park(
				mirror_addr,
				|| {
					atom.compare_exchange_weak(
						owner_tid, owner_tid | FUTEX_WAITERS, Ordering::SeqCst, Ordering::SeqCst
					).is_ok()
				},
				|| context.park_addr = mirror_addr,
				|_, _| {},
				DEFAULT_PARK_TOKEN,
				None
			);
			match res {
				ParkResult::Invalid => (),
				ParkResult::Unparked(tok) if tok == DEFAULT_UNPARK_TOKEN => {
					atom.store(atom.load(Ordering::SeqCst) & FUTEX_TID_MASK | context.tid, Ordering::SeqCst);
					break Ok(())
				},
				ParkResult::Unparked(tok) if tok == HOST_ABORTED => {
					break Err(E_WBX_HOSTABORT)
				},
				_ => panic!(),
			}
		};
		context.park_addr = 0;
		ret
	}
}

pub fn futex_unlock_pi(mirror_addr: usize) {
	unsafe {
		let atom = transmute::<_, &AtomicU32>(mirror_addr);
		unpark_one(
			mirror_addr,
			|r| {
				if r.unparked_threads == 0 {
					atom.store(0, Ordering::SeqCst);
				} else if !r.have_more_threads {
					atom.fetch_and(!FUTEX_WAITERS, Ordering::SeqCst);
				}
				DEFAULT_UNPARK_TOKEN
			}
		);
	}
}
