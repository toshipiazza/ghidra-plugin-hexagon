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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.PcodeEmitPacked;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.InstructionPcodeOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

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

	boolean hasDotNewPredicateOrNewValueOperand(PcodeOp op) {
		// $U2dd00:1 = CALLOTHER "newreg", P0
		if (op.getOpcode() != PcodeOp.CALLOTHER) {
			return false;
		}
		if (op.getNumInputs() != 2) {
			return false;
		}
		if (!op.getInput(0).isConstant()) {
			return false;
		}
		if (op.getInput(0).getOffset() != 0) {
			return false;
		}
		return op.getInput(1).isRegister();
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

	Set<Varnode> getRegsRead(Instruction instr) {
		Set<Varnode> regsReadInInstruction = new HashSet<>();
		for (Object obj : instr.getInputObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				Varnode vn = new Varnode(reg.getAddress(), reg.getNumBytes());
				regsReadInInstruction.add(vn);
			}
		}
		return regsReadInInstruction;
	}

	Set<Varnode> getRegsWritten(Instruction instr) {
		Set<Varnode> regsWrittenInInstruction = new HashSet<>();
		for (Object obj : instr.getResultObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				Varnode vn = new Varnode(reg.getAddress(), reg.getNumBytes());
				regsWrittenInInstruction.add(vn);
			}
		}
		return regsWrittenInInstruction;
	}

	boolean regWrittenInInstruction(Instruction instr, Register r) {
		for (Object obj : instr.getResultObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				if (reg.equals(r)) {
					return true;
				}
			}
		}
		return false;
	}

	Varnode getScratchReg(Instruction instr, HexagonRegisterScratchSpace regTempSpace,
			HexagonRegisterScratchSpace regTempSpaceWrite, Varnode vn) {
		Register reg = program.getRegister(vn);
		if (regWrittenInInstruction(instr, reg)) {
			return regTempSpaceWrite.getScratchVn(vn);
		} else {
			return regTempSpace.getScratchVn(vn);
		}
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

		AddressSet addrSet = new AddressSet(minAddr, maxAddr);

		HexagonRegisterScratchSpace regTempSpace = new HexagonRegisterScratchSpace(program, uniqueFactory);
		HexagonRegisterScratchSpace regTempSpaceWrite = new HexagonRegisterScratchSpace(program, uniqueFactory);

		// used for all register loads that happen before all instructions run in
		// parallel
		List<PcodeOp> phase1 = new ArrayList<PcodeOp>();

		// used for initializing conditional branch constants
		List<PcodeOp> phase2 = new ArrayList<PcodeOp>();

		// used for main pcode for all instructions
		List<PcodeOp> phase3 = new ArrayList<PcodeOp>();

		// used to writeback all registers written in phase 3
		List<PcodeOp> phase4 = new ArrayList<PcodeOp>();

		// used to resolve control flow in order that they appear in the packet
		List<PcodeOp> phase5 = new ArrayList<PcodeOp>();

		InstructionIterator insnIter = program.getListing().getInstructions(addrSet, true);
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();

			Set<Varnode> regsWrittenInInstruction = getRegsWritten(instr);

			// handle spills
			for (Varnode vn : getRegsRead(instr)) {
				if (!regsWrittenInInstruction.contains(vn)) {
					phase1.add(Copy(regTempSpace.getScratchVn(vn), vn));
				}
			}
			for (Varnode vn : regsWrittenInInstruction) {
				phase1.add(Copy(regTempSpaceWrite.getScratchVn(vn), vn));
			}

			InstructionPcodeOverride pcodeOverride = new InstructionPcodeOverride(instr);
			List<PcodeOp> ops = Arrays
					.asList(instr.getPrototype().getPcode(instr.getInstructionContext(), pcodeOverride, uniqueFactory));

			// heuristic to detect if there's been conditional control flow until now
			boolean hasConditional = false;
			boolean skipNextInstruction = false;

			for (int i = 0; i < ops.size(); i++) {
				if (skipNextInstruction) {
					skipNextInstruction = false;
					continue;
				}

				PcodeOp op = ops.get(i);
				if (hasDotNewPredicateOrNewValueOperand(op)) {
					// replace
					//
					// `$U2dd00:1 = CALLOTHER "newreg", P0`
					//
					// with
					//
					// `$U2dd00:1 = regTempSpaceWrite(P0)`
					ops.set(i, Copy(op.getOutput(), regTempSpaceWrite.getScratchVn(op.getInput(1))));
				} else {
					// replace all registers in ops with register reads
					for (int j = 0; j < op.getNumInputs(); j++) {
						if (op.getInput(j).isRegister()) {
							op.setInput(getScratchReg(instr, regTempSpace, regTempSpaceWrite, op.getInput(j)), j);
						}
					}
					if (op.getOutput() != null && op.getOutput().isRegister()) {
						op.setOutput(getScratchReg(instr, regTempSpace, regTempSpaceWrite, op.getOutput()));
					}
				}

				Varnode init = Constant(0);
				Varnode hit = Constant(1);

				switch (op.getOpcode()) {
				case PcodeOp.CALL:
				case PcodeOp.CALLIND: {
					//
					// phase2:
					// branch_taken = 0
					// phase3:
					// ...
					// branch_taken = 1
					// ...
					// phase5:
					// CBRANCH taken branch_taken
					// BRANCH done
					// taken:
					// CALL[IND] dest
					// BRANCH pkt_next
					// done:
					//
					Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
					phase2.add(Copy(vn, init));
					PcodeOp hitOp = Copy(vn, hit);
					ops.set(i, hitOp);
					Varnode pktNextVn = new Varnode(pktNext, 4);
					if (!hasConditional) {
						phase5.add(op);
					} else {
						phase5.add(Cbranch(Constant(2), vn)); // goto <taken>
						phase5.add(Branch(Constant(3))); // goto <done>
						// <taken>:
						phase5.add(op);
					}

					// Note that because both cases insert an instruction, we
					// don't need to fixup the constant relative jumps above
					if (pcodeOverride.getFlowOverride().equals(FlowOverride.CALL_RETURN)) {
						//
						// If CALL_RETURN FlowOverride is requested, then
						// getPcode() above inserted a null RETURN right after
						// the call
						//
						assert ops.get(i + 1) != null;
						assert ops.get(i + 1).getOpcode() == PcodeOp.RETURN;
						assert ops.get(i + 1).getInput(0).isConstant();
						assert ops.get(i + 1).getInput(0).getOffset() == 0;
						phase5.add(ops.get(i + 1));
						// We need to "nop" out the RETURN in ops, do so without
						// changing any relative offsets by just re-inserting
						// the hitOp (effectively a NOP)
						ops.set(i + 1, hitOp);
						// Skip the subsequent RETURN
						skipNextInstruction = true;
					} else {
						//
						// If there was no CALL_RETURN override, then we want to
						// ignore the rest of the packet when the CALL is taken
						//
						phase5.add(Branch(pktNextVn));
					}
					// <done>:
				}
					break;

				case PcodeOp.RETURN:
				case PcodeOp.BRANCH:
				case PcodeOp.BRANCHIND:
					//
					// phase2:
					// branch_taken = 0
					// phase3:
					// ...
					// branch_taken = 1
					// ...
					// phase5:
					// CBRANCH taken branch_taken
					// BRANCH done
					// taken:
					// BRANCH[ind] dest
					// done:
					//
					if (!op.getInput(0).isConstant()) {
						Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
						phase2.add(Copy(vn, init));
						ops.set(i, Copy(vn, hit));
						if (!hasConditional) {
							phase5.add(op);
						} else {
							phase5.add(Cbranch(Constant(2), vn));
							phase5.add(Branch(Constant(2)));
							phase5.add(op);
						}
					}
					break;

				case PcodeOp.CBRANCH:
					//
					// phase2:
					// branch_taken = 0
					// phase3:
					// ...
					// branch_taken = <original CBRANCH conditional>
					// ...
					// phase5:
					// CBRANCH dest branch_taken
					//
					if (!op.getInput(0).isConstant()) {
						Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
						phase2.add(Copy(vn, init));
						ops.set(i, Copy(vn, op.getInput(1)));
						phase5.add(Cbranch(op.getInput(0), vn));
					} else {
						// assume that the rest of the instruction is
						// conditional because this was a conditional branch
						hasConditional = true;
					}
					break;

				}
			}

			phase3.addAll(ops);

			for (Varnode vn : regsWrittenInInstruction) {
				phase4.add(Copy(vn, regTempSpaceWrite.getScratchVn(vn)));
			}
		}

		phase1.addAll(phase2);
		phase1.addAll(phase3);
		phase1.addAll(phase4);
		phase1.addAll(phase5);
		return phase1;
	}

	PcodeOp Cbranch(Varnode dst, Varnode vn) {
		return new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, new Varnode[] { dst, vn }, null);
	}

	PcodeOp Branch(Varnode dst) {
		return new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { dst }, null);
	}

	PcodeOp Copy(Varnode dst, Varnode src) {
		return new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { src }, dst);
	}

	Varnode Constant(int val) {
		return new Varnode(program.getAddressFactory().getConstantAddress(val), 1);
	}

	public PackedBytes getPcodePacked(InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		PackedBytes packed = new PackedBytes(100);
		writePackedBytes(getPcode(context, uniqueFactory), packed);
		return packed;
	}
}
