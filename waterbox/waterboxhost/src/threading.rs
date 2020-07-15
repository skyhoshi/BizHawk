use crate::{syscall_defs::*, context::Context};
use std::sync::atomic::{Ordering, AtomicU32};
use std::mem::transmute;
use parking_lot_core::*;

/// The return type for various syscall results
pub enum ThreadingReturn<T> {
	/// Other host code indicated to abandon the call.  Like EAGAIN, but should not be leaked to the guest
	HostAbandoned,
	/// Return to guest with this
	Complete(T),
}
pub type ThreadingResult<T> = Result<ThreadingReturn<T>, SyscallError>;

const HOST_ABORTED: UnparkToken = UnparkToken(1);

// Mirror addresses are not used because of mprotect concerns (if it's not writable, we crash, whatever),
// but because parking_lot_core requires unique addresses to operate on

pub fn futex_wait(context: &mut Context, mirror_addr: usize, compare: u32) -> ThreadingResult<()> {
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
				Ok(ThreadingReturn::Complete(()))
			},
			ParkResult::Unparked(tok) if tok == HOST_ABORTED => {
				Ok(ThreadingReturn::HostAbandoned)
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
	// Parking lot core doesn't supp
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
