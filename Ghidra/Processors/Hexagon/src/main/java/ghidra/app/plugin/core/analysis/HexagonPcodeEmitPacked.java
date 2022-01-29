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

	boolean isCallotherNewreg(PcodeOp op) {
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

	Varnode getScratchReg(Instruction instr, Varnode vn) {
		Register reg = program.getRegister(vn);
		if (regWrittenInInstruction(instr, reg)) {
			return regTempSpaceWrite.getScratchVn(vn);
		} else {
			return regTempSpace.getScratchVn(vn);
		}
	}

	class HexagonExternalBranch {
		Address insnAddress;
		FlowOverride override;
		int opcode;
		Varnode destVn;
		Varnode condVn;
		boolean hasConditional;
		int branchNoInInsn;

		HexagonExternalBranch(Instruction instr, int opcode, Varnode destVn, UniqueAddressFactory uniqueFactory,
				boolean hasConditional, int branchNoInInsn) {
			insnAddress = instr.getAddress();
			this.override = instr.getFlowOverride();
			this.opcode = opcode;
			condVn = new Varnode(uniqueFactory.getNextUniqueAddress(), 1);
			if (destVn.isRegister()) {
				this.destVn = getScratchReg(instr, destVn);

			} else {
				this.destVn = destVn;
			}
			this.hasConditional = hasConditional;
			this.branchNoInInsn = branchNoInInsn;
			if (branchNoInInsn > 0) {
				this.override = FlowOverride.NONE;
			}
		}
	}

	HexagonExternalBranch getBranchInfo(Instruction instr, int branchNoInInsn) {
		for (HexagonExternalBranch b : branches) {
			if (b.insnAddress.equals(instr.getAddress()) && b.branchNoInInsn == branchNoInInsn) {
				return b;
			}
		}
		throw new IllegalArgumentException();
	}

	Set<Varnode> allRegsWritten;

	void initializeTemporaryRegisters(InstructionIterator insnIter) {
		allRegsWritten = new HashSet<>();
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();
			Set<Varnode> regsWrittenInInstruction = getRegsWritten(instr);
			allRegsWritten.addAll(regsWrittenInInstruction);
			for (Varnode vn : getRegsRead(instr)) {
				if (!regsWrittenInInstruction.contains(vn)) {
					final_pcode.add(Copy(regTempSpace.getScratchVn(vn), vn));
				}
			}
			for (Varnode vn : regsWrittenInInstruction) {
				final_pcode.add(Copy(regTempSpaceWrite.getScratchVn(vn), vn));
			}
		}
	}

	static final Set<String> new_cmp_jumps;

	static {
		new_cmp_jumps = new HashSet<>();
		new_cmp_jumps.add("J4_cmpeqi_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeqi_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeqi_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpeqi_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpeqi_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeqi_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeqi_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpeqi_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpgti_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgti_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgti_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpgti_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpgti_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgti_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgti_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpgti_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtui_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtui_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtui_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtui_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtui_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtui_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtui_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtui_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpeqn1_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeqn1_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeqn1_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpeqn1_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpeqn1_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeqn1_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeqn1_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpeqn1_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtn1_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtn1_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtn1_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtn1_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtn1_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtn1_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtn1_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtn1_fp1_jump_t");
		new_cmp_jumps.add("J4_tstbit0_tp0_jump_nt");
		new_cmp_jumps.add("J4_tstbit0_fp0_jump_nt");
		new_cmp_jumps.add("J4_tstbit0_tp0_jump_t");
		new_cmp_jumps.add("J4_tstbit0_fp0_jump_t");
		new_cmp_jumps.add("J4_tstbit0_tp1_jump_nt");
		new_cmp_jumps.add("J4_tstbit0_fp1_jump_nt");
		new_cmp_jumps.add("J4_tstbit0_tp1_jump_t");
		new_cmp_jumps.add("J4_tstbit0_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpeq_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeq_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpeq_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpeq_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpeq_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeq_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpeq_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpeq_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpgt_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgt_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgt_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpgt_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpgt_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgt_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgt_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpgt_fp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtu_tp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtu_fp0_jump_nt");
		new_cmp_jumps.add("J4_cmpgtu_tp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtu_fp0_jump_t");
		new_cmp_jumps.add("J4_cmpgtu_tp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtu_fp1_jump_nt");
		new_cmp_jumps.add("J4_cmpgtu_tp1_jump_t");
		new_cmp_jumps.add("J4_cmpgtu_fp1_jump_t");
	}

	boolean isNewCmpJumpInstruction(Instruction instr) {
		// NEWCMPJUMP instructions are single 4-byte instructions of the form
		//
		// p0=cmp.eq(Rs16,#U5)
		// if (!p0.new) jump:nt #r9:2
		//
		// such instructions both write a predicate and read a predicate in the same
		// instruction, so they must come before any other instruction in the packet
		// thats reads that dot-new predicate
		return new_cmp_jumps.contains(instr.getMnemonicString());
	}

	boolean doesInstructionContainDotNewPredicate(Instruction instr) {
		// any (non-NEWCMPJMP) instruction that reads a dot-new predicate should be
		// handled after all other instructions, to give a "future" producer the chance
		// to perform the store
		if (HexagonPacketInfo.dot_new_predicates.containsKey(instr.getMnemonicString())
				|| HexagonPacketInfo.dot_new_predicates_operands.contains(instr.getMnemonicString())) {
			return true;
		}
		return false;
	}

	List<Instruction> newCmpJumpInstructions;

	List<Instruction> instructionsContainingDotNewPredicates;

	Set<Varnode> regsWrittenSoFar;

	boolean isPredicateRegister(Varnode vn) {
		if (!vn.isRegister()) {
			return false;
		}
		if (vn.getSize() != 1) {
			return false;
		}
		if (program.getRegister("P0").getAddress().equals(vn.getAddress())) {
			return true;
		}
		if (program.getRegister("P1").getAddress().equals(vn.getAddress())) {
			return true;
		}
		if (program.getRegister("P2").getAddress().equals(vn.getAddress())) {
			return true;
		}
		if (program.getRegister("P3").getAddress().equals(vn.getAddress())) {
			return true;
		}
		return false;
	}

	void processInstructionsBesidesDotNewPredicates(InstructionIterator insnIter) throws UnknownInstructionException {
		newCmpJumpInstructions = new ArrayList<>();
		instructionsContainingDotNewPredicates = new ArrayList<>();
		while (insnIter.hasNext()) {
			Instruction instr = insnIter.next();
			if (isNewCmpJumpInstruction(instr)) {
				newCmpJumpInstructions.add(instr);
				continue;
			}
			if (doesInstructionContainDotNewPredicate(instr)) {
				instructionsContainingDotNewPredicates.add(instr);
				continue;
			}

			final_pcode.addAll(fixupPcode(instr));
		}
	}

	void processNewCmpJumpInstructions() throws UnknownInstructionException {
		for (Instruction instr : newCmpJumpInstructions) {
			final_pcode.addAll(fixupPcode(instr));
		}
	}

	void processInstructionsContainingDotNewPredicates() throws UnknownInstructionException {
		for (Instruction instr : instructionsContainingDotNewPredicates) {
			final_pcode.addAll(fixupPcode(instr));
		}
	}

	void resolveAllStores() {
		for (Varnode vn : allRegsWritten) {
			final_pcode.add(Copy(vn, regTempSpaceWrite.getScratchVn(vn)));
		}
	}

	void insertBranch(boolean conditional, Varnode branchVn, PcodeOp origBranchOp) {
		if (!conditional) {
			final_pcode.add(origBranchOp);
		} else {
			final_pcode.add(Cbranch(Constant(2), branchVn));
			final_pcode.add(Branch(Constant(2)));
			final_pcode.add(origBranchOp);
		}
	}

	void insertCall(boolean conditional, Varnode branchVn, PcodeOp origCallOp, boolean callReturnOverride) {
		Varnode pktNextVn = new Varnode(pktNext, 4);
		if (!conditional) {
			final_pcode.add(origCallOp);
		} else {
			final_pcode.add(Cbranch(Constant(2), branchVn)); // goto <taken>
			final_pcode.add(Branch(Constant(3))); // goto <done>
			// <taken>:
			final_pcode.add(origCallOp);
		}
		// note that both cases below insert exactly one instruction, so the relative
		// jumps above are constant
		if (callReturnOverride) {
			// if CALL_RETURN FlowOverride is requested, then inject a return [0] after
			final_pcode.add(Return(Constant(0)));
		} else {
			// if there was no override, we still need to ignore the rest of the packet if
			// the call is hit
			final_pcode.add(Branch(pktNextVn));
		}
		// <done>:
	}

	void insertCbranch(Varnode branchVn, Varnode destVn) {
		final_pcode.add(Cbranch(destVn, branchVn));
	}

	void resolveAllBranches() {
		for (HexagonExternalBranch br : branches) {
			switch (br.override) {
			case BRANCH:
				insertBranch(br.hasConditional, br.condVn, Branch(br.destVn));
				break;
			case CALL:
				insertCall(br.hasConditional, br.condVn, Call(br.destVn), false);
				break;
			case CALL_RETURN:
				insertCall(br.hasConditional, br.condVn, Call(br.destVn), true);
				break;
			case RETURN:
				insertBranch(br.hasConditional, br.condVn, Return(Constant(0)));
				break;
			case NONE:
				assert !br.destVn.isConstant();
				switch (br.opcode) {
				case PcodeOp.BRANCH:
				case PcodeOp.BRANCHIND:
					insertBranch(br.hasConditional, br.condVn, Branch(br.destVn));
					break;
				case PcodeOp.CALL:
				case PcodeOp.CALLIND:
					insertCall(br.hasConditional, br.condVn, Call(br.destVn), false);
					break;
				case PcodeOp.CBRANCH:
					insertCbranch(br.condVn, br.destVn);
					assert false;
					break;
				case PcodeOp.RETURN:
					insertBranch(br.hasConditional, br.condVn, Return(br.destVn));
					break;
				default:
					assert false;
					break;
				}
				break;
			}
		}
	}

	void checkPcodeUnimplemented(Instruction insn, PcodeOp[] ops) throws UnknownInstructionException {
		if (ops.length == 1 && ops[0].getOpcode() == PcodeOp.UNIMPLEMENTED) {
			throw new UnknownInstructionException("Unimplemented instruction " + insn);
		}
	}

	List<HexagonExternalBranch> branches;

	List<PcodeOp> fixupPcode(Instruction instr) throws UnknownInstructionException {
		List<PcodeOp> ops = Arrays.asList(instr.getPrototype().getPcode(instr.getInstructionContext(), null, null));
		for (int i = 0; i < ops.size(); i++) {
			PcodeOp op = ops.get(i);
			if (isCallotherNewreg(op)) {
				// new-value operand/dot-new predicate must have been written earlier in packet
				assert op.getInput(1).isRegister();
				assert regsWrittenSoFar.contains(op.getInput(1));
				ops.set(i, Copy(op.getOutput(), regTempSpaceWrite.getScratchVn(op.getInput(1))));
			} else {
				// replace all registers with appropriate scratch regs
				for (int j = 0; j < op.getNumInputs(); j++) {
					if (op.getInput(j).isRegister()) {
						op.setInput(getScratchReg(instr, op.getInput(j)), j);
					}
				}
				if (op.getOutput() != null && op.getOutput().isRegister()) {
					regsWrittenSoFar.add(op.getOutput());
					if (isPredicateRegister(op.getOutput())) {
						// TODO: handle auto-and predicate
						op.setOutput(getScratchReg(instr, op.getOutput()));
					} else {
						op.setOutput(getScratchReg(instr, op.getOutput()));
					}
				}
			}

			Varnode hit = Constant(1);
			int branchNoInInsn = 0;
			switch (op.getOpcode()) {
			case PcodeOp.CALL:
			case PcodeOp.CALLIND:
			case PcodeOp.RETURN:
			case PcodeOp.BRANCH:
			case PcodeOp.BRANCHIND:
				if (!op.getInput(0).isConstant()) {
					HexagonExternalBranch br = getBranchInfo(instr, branchNoInInsn);
					assert br.opcode == op.getOpcode();
					PcodeOp hitOp = Copy(br.condVn, hit);
					ops.set(i, hitOp);
					branchNoInInsn++;
				}
				break;
			case PcodeOp.CBRANCH:
				if (!op.getInput(0).isConstant()) {
					HexagonExternalBranch br = getBranchInfo(instr, branchNoInInsn);
					assert br.opcode == op.getOpcode();
					PcodeOp hitOp = Copy(br.condVn, op.getInput(1));
					ops.set(i, hitOp);
					branchNoInInsn++;
				}
				break;
			}
		}
		return ops;
	}

	void recordBranchesAndValidateImplementedPcode(InstructionIterator insnIter, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		Varnode init = Constant(0);
		branches = new ArrayList<>();

		while (insnIter.hasNext()) {
			Instruction insn = insnIter.next();
			// explicitly request no pcode override behavior because we will handle it
			// ourselves
			PcodeOp[] ops = insn.getPrototype().getPcode(insn.getInstructionContext(), null, null);
			checkPcodeUnimplemented(insn, ops);
			int branchNoInInsn = 0;
			boolean hasConditional = false;
			for (PcodeOp op : ops) {
				switch (op.getOpcode()) {
				case PcodeOp.RETURN:
				case PcodeOp.CALLIND:
				case PcodeOp.BRANCHIND:
				case PcodeOp.BRANCH:
				case PcodeOp.CALL:
				case PcodeOp.CBRANCH:
					if (op.getInput(0).isConstant()) {
						if (op.getOpcode() == PcodeOp.CBRANCH) {
							hasConditional = true;
						}
					} else {
						HexagonExternalBranch br = new HexagonExternalBranch(insn, op.getOpcode(), op.getInput(0),
								uniqueFactory, hasConditional, branchNoInInsn);
						branches.add(br);
						final_pcode.add(Copy(br.condVn, init));
						branchNoInInsn++;
					}
					break;
				}
			}
		}
	}

	HexagonRegisterScratchSpace regTempSpace;

	HexagonRegisterScratchSpace regTempSpaceWrite;

	List<PcodeOp> final_pcode;

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

		regTempSpace = new HexagonRegisterScratchSpace(program, uniqueFactory);
		regTempSpaceWrite = new HexagonRegisterScratchSpace(program, uniqueFactory);

		regsWrittenSoFar = new HashSet<>(); // debugging tool

		final_pcode = new ArrayList<PcodeOp>();

		//
		// General strategy is similar to binja-hexagon
		//
		// 1. First, all registers used into the packet are spilled into temporaries in
		// either regTempSpace or regTempSpaceWrite
		//
		// 2. All branches in the packet are recorded in the order they appear in the
		// packet. Record and initialize a "branch var" that records whether that branch
		// is taken
		//
		// 3. Copy pcode for all instructions (besides instructions containing dot-new
		// predicates). Replace all registers with their appropriate temporaries
		//
		// 4. Copy pcode for all newcmpjump instructions
		//
		// 5. Copy pcode for all other instructions containing dot-new predicates
		//
		// 6. Resolve all register stores
		//
		// 7. Resolve the correct branch destination in priority of the order each
		// branch appears in the packet
		//
		// Some interesting comments:
		//
		// - Steps 4 and 5 are required because dot-new predicates (p0.new) can occur
		// anywhere in the packet, before the corresponding store to the predicate. So
		// we process all instructions that contain a dot-new predicate after the rest
		// of the instructions have been processed.
		//
		// Note that NewCmpJump instructions are those which both write a predicate
		// register and read that dot-new predicate
		//
		// - new-value operands do not have the problem above, because new-value
		// operands are encoded with a constant indicating a *previous* instruction in
		// the packet. So the new-value producer must come earlier in the packet
		//
		// - TODO: Currently auto-and predicates are not supported
		//
		// - Code assumes that there is at most one external branch in every
		// instruction, not including fallthrough. endloop01 is the only exception
		//
		// - Emitted pcode respects flow overrides and handles them appropriately
		//

		initializeTemporaryRegisters(program.getListing().getInstructions(addrSet, true));

		recordBranchesAndValidateImplementedPcode(program.getListing().getInstructions(addrSet, true), uniqueFactory);

		processInstructionsBesidesDotNewPredicates(program.getListing().getInstructions(addrSet, true));

		processNewCmpJumpInstructions();

		processInstructionsContainingDotNewPredicates();

		resolveAllStores();

		resolveAllBranches();

		return final_pcode;
	}

	PcodeOp Call(Varnode rv) {
		if (rv.isRegister() || rv.isUnique()) {
			return new PcodeOp(defaultSeqno, PcodeOp.CALLIND, new Varnode[] { rv }, null);
		} else {
			return new PcodeOp(defaultSeqno, PcodeOp.CALL, new Varnode[] { rv }, null);
		}
	}

	PcodeOp Return(Varnode rv) {
		return new PcodeOp(defaultSeqno, PcodeOp.RETURN, new Varnode[] { rv }, null);
	}

	PcodeOp Cbranch(Varnode dst, Varnode vn) {
		return new PcodeOp(defaultSeqno, PcodeOp.CBRANCH, new Varnode[] { dst, vn }, null);
	}

	PcodeOp Branch(Varnode dst) {
		if (dst.isRegister() || dst.isUnique()) {
			return new PcodeOp(defaultSeqno, PcodeOp.BRANCHIND, new Varnode[] { dst }, null);
		} else {
			return new PcodeOp(defaultSeqno, PcodeOp.BRANCH, new Varnode[] { dst }, null);
		}
	}

	PcodeOp Copy(Varnode dst, Varnode src) {
		return new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { src }, dst);
	}

	PcodeOp And(Varnode dst, Varnode src) {
		return new PcodeOp(defaultSeqno, PcodeOp.COPY, new Varnode[] { dst, src }, dst);
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
