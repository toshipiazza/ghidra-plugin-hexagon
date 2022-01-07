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

import ghidra.app.plugin.processors.sleigh.PcodeEmitPacked;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

import java.math.BigInteger;
import java.util.*;

public class HexagonPcodeEmitPacked {

	Program program;

	Address minAddr;
	Address maxAddr;
	Address pktNext;
	long packetSize;

	// the sequence number does not matter for our purposes, so just keep a
	// default one around
	SequenceNumber defaultSeqno;

	HexagonPcodeEmitPacked(Program program) {
		this.program = program;
	}

	Address getRegisterTemp(Address[] scratchRegUnique, Address addr) {
		return scratchRegUnique[(int) (addr.getOffset() / 4)].add(addr.getOffset() % 4);
	}

	boolean branchRequiresFixup(PcodeOp op) {
		if (op.getOpcode() == PcodeOp.CBRANCH || op.getOpcode() == PcodeOp.BRANCH) {
			// constant cbranches are pcode-relative and don't need to be fixed up
			return !op.getInput(0).isConstant();
		}
		return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND
				|| op.getOpcode() == PcodeOp.BRANCHIND || op.getOpcode() == PcodeOp.RETURN;
	}

	boolean isCall(PcodeOp op) {
		return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
	}

	void analyzePcode(Instruction instruction, PcodeOp[] pcode, UniqueAddressFactory uniqueFactory,
			Address[] scratchRegUnique, Set<Varnode> registerSpills, Map<SequenceNumber, Varnode> branches) {

		// identify all the registers which need to be spilled up top and control flow
		// to be patched
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); ++i) {
				Address addr = op.getInput(i).getAddress();
				if (addr.getAddressSpace().getName().equals("register")) {
					registerSpills.add(op.getInput(i));
				}
			}
			if (branchRequiresFixup(op)) {
				branches.put(op.getSeqnum(), new Varnode(uniqueFactory.getNextUniqueAddress(), 1));
			}
		}
	}

	void initBranches(List<PcodeOp> uniqPcode, Map<SequenceNumber, Varnode> branches, AddressFactory addressFactory) {
		for (Varnode branchVn : branches.values()) {
			Varnode[] in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(0), 1) };
			PcodeOp spill = new PcodeOp(defaultSeqno, PcodeOp.COPY, in, branchVn);
			uniqPcode.add(spill);
		}
	}

	void spillRegs(List<PcodeOp> uniqPcode, Address[] scratchRegUnique, Set<Varnode> registerSpills) {
		for (Varnode reg : registerSpills) {
			Address uniq = getRegisterTemp(scratchRegUnique, reg.getAddress());
			Varnode[] in = new Varnode[] { reg };
			Varnode out = new Varnode(uniq, reg.getSize());
			PcodeOp spill = new PcodeOp(defaultSeqno, PcodeOp.COPY, in, out);
			uniqPcode.add(spill);
		}
	}

	boolean hasFallthrough(Instruction insn) {
		return insn.getPrototype().getFallThrough(insn.getInstructionContext()) != null;
	}

	boolean isNewRegUserOp(PcodeOp op) {
		if (op.getOpcode() != PcodeOp.CALLOTHER) {
			return false;
		}

		if (op.getNumInputs() != 2) {
			return false;
		}

		if (!op.getInput(0).isConstant()) {
			return false;
		}

		return op.getInput(0).getOffset() == 0;
	}

	void writePcode(Instruction instruction, PcodeOp[] pcode, List<PcodeOp> mainPcode, List<PcodeOp> jumpPcode,
			UniqueAddressFactory uniqueFactory, Address[] scratchRegUnique, Set<Varnode> registerSpills,
			Map<SequenceNumber, Varnode> branches, AddressFactory addressFactory) {
		for (int j = 0; j < pcode.length; j++) {
			PcodeOp op = pcode[j];
			PcodeOp opNew;
			if (isNewRegUserOp(op)) {

				opNew = new PcodeOp(defaultSeqno, PcodeOp.COPY, 1, op.getOutput());

				if (op.getInput(1).isRegister()) {
					// Replace dot-new predicate of the form
					//
					// $U2dd00:1 = CALLOTHER "newreg", P0
					//
					// With:
					//
					// $U2dd00:1 = P0
					//
					opNew.setInput(op.getInput(1), 0);
				} else {
					// Replace new-value operand of the form
					//
					// $U47d80:4 = LOAD register(R6)
					// $U47d00:4 = CALLOTHER "newreg", $U47d80:4
					//
					// With:
					//
					// $U47d00:4 = R6
					assert j != 0;
					PcodeOp opLoad = pcode[j - 1];
					assert opLoad.getOpcode() == PcodeOp.LOAD;
					assert opLoad.getInput(0).getAddress().isConstantAddress();
					assert opLoad.getInput(0).getAddress().getOffset() == program.getAddressFactory().getRegisterSpace()
							.getSpaceID();
					assert opLoad.getInput(1).isRegister();
					assert opLoad.getOutput().equals(op.getInput(1));

					opNew.setInput(opLoad.getInput(1), 0);
				}
			} else {
				opNew = new PcodeOp(defaultSeqno, op.getOpcode(), op.getNumInputs(), op.getOutput());
				for (int i = 0; i < op.getNumInputs(); i++) {
					if (op.getInput(i).getAddress().getAddressSpace().getName().equals("register")) {
						Address uniq = getRegisterTemp(scratchRegUnique, op.getInput(i).getAddress());
						opNew.setInput(new Varnode(uniq, op.getInput(i).getSize()), i);
					} else {
						opNew.setInput(op.getInput(i), i);
					}
				}
			}
			if (branchRequiresFixup(opNew)) {
				Varnode branchVn = branches.get(op.getSeqnum());

				InstructionPcodeOverride override = new InstructionPcodeOverride(instruction);
				// jump to next instruction in case of a call, so we don't
				// fallthrough to another jump
				// the one exception to this is a CALL_RETURN flow override,
				// which will append a RETURN right after the CALL
				boolean insert_jump_after_packet = isCall(op)
						&& !override.getFlowOverride().equals(FlowOverride.CALL_RETURN);

				if (hasFallthrough(instruction)) {
					Varnode[] in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(1), 1) };
					PcodeOp spill = new PcodeOp(defaultSeqno, PcodeOp.COPY, in, branchVn);
					mainPcode.add(spill);

					int disp = 2;
					if (insert_jump_after_packet) {
						disp = 3;
					}

					in = new Varnode[] { branchVn };
					Varnode out = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
					PcodeOp insn1 = new PcodeOp(defaultSeqno, PcodeOp.BOOL_NEGATE, in, out);
					jumpPcode.add(insn1);
					in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(disp), 1), out };
					PcodeOp insn2 = new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, in, null);
					jumpPcode.add(insn2);
				}

				jumpPcode.add(opNew);

				if (insert_jump_after_packet) {
					Varnode[] in = new Varnode[] { new Varnode(pktNext, 4) };
					PcodeOp insn2 = new PcodeOp(defaultSeqno, PcodeOp.BRANCH, in, null);
					jumpPcode.add(insn2);
				}
			} else {
				mainPcode.add(opNew);
			}
		}
	}

	void writeOffset(PackedBytes buf, long val) {
		while (val != 0) {
			int chunk = (int) (val & 0x3f);
			val >>>= 6;
			buf.write(chunk + 0x20);
		}
		buf.write(PcodeEmitPacked.end_tag);
	}

	void dump(PackedBytes buf, int opcode, Varnode[] in, int isize, Varnode out) {
		buf.write(PcodeEmitPacked.op_tag);
		buf.write(opcode + 0x20);
		if (out == null) {
			buf.write(PcodeEmitPacked.void_tag);
		} else {
			dumpVarnodeData(buf, out);
		}
		int i = 0;
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			dumpSpaceId(buf, in[0]);
			i = 1;
		}
		for (; i < isize; ++i) {
			dumpVarnodeData(buf, in[i]);
		}
		buf.write(PcodeEmitPacked.end_tag);
	}

	private void dumpSpaceId(PackedBytes buf, Varnode v) {
		buf.write(PcodeEmitPacked.spaceid_tag);
		int spcindex = ((int) v.getOffset() >> AddressSpace.ID_UNIQUE_SHIFT);
		buf.write(spcindex + 0x20);
	}

	void dumpVarnodeData(PackedBytes buf, Varnode v) {
		buf.write(PcodeEmitPacked.addrsz_tag);
		int spcindex = v.getAddress().getAddressSpace().getUnique();
		buf.write(spcindex + 0x20);
		writeOffset(buf, v.getOffset());
		buf.write(v.getSize() + 0x20);
	}

	void writePackedBytes(List<PcodeOp> pcode, PackedBytes buf) {
		buf.write(PcodeEmitPacked.inst_tag);
		writeOffset(buf, packetSize);

		Address pktAddr = minAddr;
		int spcindex = pktAddr.getAddressSpace().getUnique();
		buf.write(spcindex + 0x20);
		writeOffset(buf, pktAddr.getOffset());

		for (PcodeOp op : pcode) {
			dump(buf, op.getOpcode(), op.getInputs(), op.getNumInputs(), op.getOutput());
		}

		buf.write(PcodeEmitPacked.end_tag);
	}

	public List<PcodeOp> getPcode(InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		BigInteger pkt_start = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("pkt_start"), context.getAddress(), false);
		if (pkt_start == null) {
			// not yet analyzed
			throw new UnknownInstructionException("Packet not yet analyzed");
		}
		if (!context.getAddress().getOffsetAsBigInteger().equals(pkt_start)) {
			throw new UnknownInstructionException("Attempting to get pcode from the middle of a packet");
		}

		minAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_start.longValue());

		defaultSeqno = new SequenceNumber(minAddr, 0);

		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				context.getAddress(), false);
		if (pkt_next == null) {
			// not yet analyzed
			throw new UnknownInstructionException("Packet not yet analyzed");
		}

		pktNext = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_next.longValue());
		maxAddr = pktNext.subtract(1);

		packetSize = pkt_next.subtract(pkt_start).intValue();

		List<PcodeOp> uniqPcode = new ArrayList<>();
		List<PcodeOp> mainPcode = new ArrayList<>();
		List<PcodeOp> jumpPcode = new ArrayList<>();

		Set<Varnode> registerSpills = new HashSet<>();
		Map<SequenceNumber, Varnode> branches = new HashMap<>();

		// Registers R1R0 aliases with R1 and R0, so their scratch regs must too
		// 96 registers R0 to R31, C0 to R31, G0 to G31, S0 to S127
		// XXX: pull this from the slaspec somehow?
		Address[] scratchRegUnique = new Address[224];

		for (int i = 0; i < scratchRegUnique.length; i += 2) {
			Address uniq = uniqueFactory.getNextUniqueAddress();
			scratchRegUnique[i + 0] = uniq.add(0);
			scratchRegUnique[i + 1] = uniq.add(4);
		}

		AddressSet addrSet = new AddressSet(minAddr, maxAddr);

		InstructionIterator insnIter = program.getListing().getInstructions(addrSet, true);
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();
			PcodeOp[] pcode = instr.getPrototype().getPcode(instr.getInstructionContext(),
					new InstructionPcodeOverride(instr), uniqueFactory);
			analyzePcode(instr, pcode, uniqueFactory, scratchRegUnique, registerSpills, branches);
		}

		initBranches(uniqPcode, branches, program.getAddressFactory());
		spillRegs(uniqPcode, scratchRegUnique, registerSpills);

		insnIter = program.getListing().getInstructions(addrSet, true);
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();
			PcodeOp[] pcode = instr.getPrototype().getPcode(instr.getInstructionContext(),
					new InstructionPcodeOverride(instr), uniqueFactory);
			writePcode(instr, pcode, mainPcode, jumpPcode, uniqueFactory, scratchRegUnique, registerSpills, branches,
					program.getAddressFactory());
		}

		List<PcodeOp> donePcode = new ArrayList<>();
		donePcode.addAll(uniqPcode);
		donePcode.addAll(mainPcode);
		donePcode.addAll(jumpPcode);

		return donePcode;
	}

	public PackedBytes getPcodePacked(InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		PackedBytes packed = new PackedBytes(100);
		writePackedBytes(getPcode(context, uniqueFactory), packed);
		return packed;
	}
}
