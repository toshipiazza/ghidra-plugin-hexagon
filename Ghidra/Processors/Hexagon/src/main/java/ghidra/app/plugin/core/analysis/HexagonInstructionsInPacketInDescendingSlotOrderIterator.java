/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.Iterator;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;

public class HexagonInstructionsInPacketInDescendingSlotOrderIterator implements InstructionIterator {

	InstructionIterator insnIter;
	Instruction slot0Duplex;

	//
	// We want to iterate over instructions in a packet in descending "slot"
	// order, e.g. 3, 2, 1, then 0
	//
	// Normally instructions are already ordered in memory in decreasing
	// slot order, except for duplex instructions. The "earlier" duplex
	// instruction is the slot 0 duplex, followed by the slot 1 duplex. We
	// need to "swap" duplex instructions in the iterator
	//
	// This edge case with duplex instructions is only problematic when
	// considering slot 1 loads with slot 1 stores. memops are satisfied in
	// descending slot order, so a packet like
	//
	// { SS2_storewi0 R2 <addr>, 0x0,
	// SL1_loadri_io R3, R2 <addr>, 0x0 }
	//
	// needs to resolve the load to R3 from R2 before the store to R2
	//
	public HexagonInstructionsInPacketInDescendingSlotOrderIterator(Program program, Address address)
			throws UnknownInstructionException {
		BigInteger pkt_start = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("pkt_start"), address, false);
		if (pkt_start == null) {
			throw new UnknownInstructionException("Packet not yet analyzed");
		}
		if (!address.getOffsetAsBigInteger().equals(pkt_start)) {
			throw new UnknownInstructionException("Attempting to iterate from the middle of a packet");
		}

		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				address, false);
		if (pkt_next == null) {
			throw new UnknownInstructionException("Packet not yet analyzed");
		}

		Address minAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_start.longValue());
		Address pktNext = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_next.longValue());
		Address maxAddr = pktNext.subtract(1);
		AddressSet addrSet = new AddressSet(minAddr, maxAddr);
		insnIter = program.getListing().getInstructions(addrSet, true);
		slot0Duplex = null;
	}

	@Override
	public boolean hasNext() {
		if (slot0Duplex != null) {
			return true;
		}
		return insnIter.hasNext();
	}

	@Override
	public Instruction next() {
		Instruction n;
		if (slot0Duplex != null) {
			assert !insnIter.hasNext();
			n = slot0Duplex;
			slot0Duplex = null;
		} else {
			n = insnIter.next();
			if (n.getLength() == 2) {
				slot0Duplex = n;
				assert insnIter.hasNext();
				n = insnIter.next();
				assert n.getLength() == 2;
			}
		}
		return n;
	}

	@Override
	public Iterator<Instruction> iterator() {
		return this;
	}

}
