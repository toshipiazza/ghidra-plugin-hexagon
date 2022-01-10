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
import ghidra.util.exception.NotYetImplementedException;

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

		HexagonRegisterScratchSpace wSpace = new HexagonRegisterScratchSpace(program, uniqueFactory);
		HexagonRegisterScratchSpace rSpace = new HexagonRegisterScratchSpace(program, uniqueFactory);

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

		// TODO: change to addrset
		Set<Varnode> regsWritten = new HashSet<>();
		Set<Varnode> regsRead = new HashSet<>();

		InstructionIterator insnIter = program.getListing().getInstructions(addrSet, true);
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();

			// TODO: support flow overrides
			List<PcodeOp> ops = Arrays
					.asList(instr.getPrototype().getPcode(instr.getInstructionContext(), null, uniqueFactory));

			// first pass to find all read vs written regs
			Set<Varnode> regsReadInInstruction = new HashSet<>();
			Set<Varnode> regsWrittenInInstruction = new HashSet<>();
			for (PcodeOp op : ops) {
				if (!hasDotNewPredicateOrNewValueOperand(op)) {
					for (int i = 0; i < op.getNumInputs(); i++) {
						if (op.getInput(i).getAddress().getAddressSpace()
								.equals(program.getAddressFactory().getRegisterSpace())) {
							regsReadInInstruction.add(op.getInput(i));
						}
					}
				}
				if (op.getOutput() != null && op.getOutput().getAddress().getAddressSpace()
						.equals(program.getAddressFactory().getRegisterSpace())) {
					regsWrittenInInstruction.add(op.getOutput());
				}
			}
			regsWritten.addAll(regsWrittenInInstruction);
			regsRead.addAll(regsReadInInstruction);

			// handle spills
			for (Varnode vn : regsReadInInstruction) {
				if (!regsWrittenInInstruction.contains(vn)) {
					phase1.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { vn },
							regTempSpace.getScratchVn(vn)));
				}
			}
			for (Varnode vn : regsWrittenInInstruction) {
				phase1.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { vn },
						regTempSpaceWrite.getScratchVn(vn)));
			}

			// heuristic to detect if there's been conditional control flow until now
			boolean hasConditional = false;

			for (int i = 0; i < ops.size(); i++) {
				PcodeOp op = ops.get(i);
				if (hasDotNewPredicateOrNewValueOperand(op)) {
					// replace `$U2dd00:1 = CALLOTHER "newreg", P0` with
					// `$U2dd00:1 = regTempSpaceWrite(P0)`
					ops.set(i, new PcodeOp(defaultSeqno, PcodeOp.COPY,
							new Varnode[] { regTempSpaceWrite.getScratchVn(op.getInput(1)) }, op.getOutput()));
				} else {
					// replace all registers in ops with register reads
					for (int j = 0; j < op.getNumInputs(); j++) {
						if (op.getInput(j).getAddress().getAddressSpace()
								.equals(program.getAddressFactory().getRegisterSpace())) {
							if (regsWrittenInInstruction.contains(op.getInput(j))) {
								op.setInput(regTempSpaceWrite.getScratchVn(op.getInput(j)), j);
							} else {
								op.setInput(regTempSpace.getScratchVn(op.getInput(j)), j);
							}
						}
					}
					if (op.getOutput() != null && op.getOutput().getAddress().getAddressSpace()
							.equals(program.getAddressFactory().getRegisterSpace())) {
						if (regsWrittenInInstruction.contains(op.getOutput())) {
							op.setOutput(regTempSpaceWrite.getScratchVn(op.getOutput()));
						} else {
							op.setOutput(regTempSpace.getScratchVn(op.getOutput()));
						}
					}
				}
				Varnode init = new Varnode(program.getAddressFactory().getConstantAddress(0), 1);
				Varnode hit = new Varnode(program.getAddressFactory().getConstantAddress(1), 1);

				switch (op.getOpcode()) {
				case PcodeOp.CALL:
				case PcodeOp.CALLIND: {
					Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
					phase2.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { init }, vn));
					ops.set(i, new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { hit }, vn));
					Varnode pktNextVn = new Varnode(pktNext, 4);
					if (!hasConditional) {
						phase5.add(op);
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { pktNextVn }, null));
					} else {
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, new Varnode[] { Constant(2), vn }, null));
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { Constant(3) }, null));
						phase5.add(op);
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { pktNextVn }, null));
					}
				}
					break;
				case PcodeOp.RETURN:
				case PcodeOp.BRANCH:
				case PcodeOp.BRANCHIND:
					if (!op.getInput(0).isConstant()) {
						Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
						phase2.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { init }, vn));
						ops.set(i, new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { hit }, vn));
						if (!hasConditional) {
							phase5.add(op);
						} else {
							phase5.add(new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, new Varnode[] { Constant(2), vn },
									null));
							phase5.add(new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { Constant(2) }, null));
							phase5.add(op);
						}
					}
					break;
				case PcodeOp.CBRANCH:
					if (!op.getInput(0).isConstant()) {
						Varnode vn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
						phase2.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { init }, vn));
						ops.set(i, new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { op.getInput(1) }, vn));
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, new Varnode[] { Constant(2), vn }, null));
						phase5.add(new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { Constant(2) }, null));
						phase5.add(op);
					} else {
						hasConditional = true;
					}
					break;
				}
			}

			phase3.addAll(ops);

			for (Varnode vn : regsWrittenInInstruction) {
				phase4.add(new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { regTempSpaceWrite.getScratchVn(vn) },
						vn));
			}
		}

		phase1.addAll(phase2);
		phase1.addAll(phase3);
		phase1.addAll(phase4);
		phase1.addAll(phase5);
		return phase1;
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
