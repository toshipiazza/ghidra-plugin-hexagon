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
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.PcodeEmitPacked;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.lang.InsufficientBytesException;
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.lang.ProcessorContext;
import ghidra.program.model.lang.ProcessorContextImpl;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class HexagonPcodeEmitPacked {

	Program program;

	Register part1Register;
	Register part2Register;

	Address minAddr;
	Address maxAddr;
	Address pktNext;
	long packetSize;

	// the sequence number does not matter for our purposes, so just keep a
	// default one around
	SequenceNumber defaultSeqno;

	HexagonPcodeEmitPacked(Program program) {
		this.program = program;
		part1Register = program.getProgramContext().getRegister("part1");
		part2Register = program.getProgramContext().getRegister("part2");

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

	static final Map<String, Integer> dot_new_predicates;

	static {
		dot_new_predicates = new HashMap<>();
		dot_new_predicates.put("J4_cmpeqi_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqi_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqi_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqi_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgti_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgti_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgti_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgti_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtui_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtui_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtui_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtui_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqn1_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqn1_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqn1_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqn1_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtn1_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtn1_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtn1_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtn1_fp0_jump_t", 0);
		dot_new_predicates.put("J4_tstbit0_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_tstbit0_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_tstbit0_tp0_jump_t", 0);
		dot_new_predicates.put("J4_tstbit0_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeq_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeq_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeq_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeq_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgt_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgt_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgt_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgt_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtu_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtu_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtu_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtu_fp0_jump_t", 0);
		dot_new_predicates.put("SA1_clrtnew", 0);
		dot_new_predicates.put("SA1_clrfnew", 0);
		dot_new_predicates.put("SL2_return_tnew", 0);
		dot_new_predicates.put("SL2_return_fnew", 0);
		dot_new_predicates.put("SL2_jumpr31_tnew", 0);
		dot_new_predicates.put("SL2_jumpr31_fnew", 0);
		dot_new_predicates.put("J4_cmpeqi_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqi_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqi_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqi_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgti_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgti_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgti_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgti_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtui_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtui_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtui_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtui_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqn1_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqn1_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqn1_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqn1_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtn1_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtn1_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtn1_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtn1_fp1_jump_t", 1);
		dot_new_predicates.put("J4_tstbit0_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_tstbit0_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_tstbit0_tp1_jump_t", 1);
		dot_new_predicates.put("J4_tstbit0_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeq_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeq_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeq_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeq_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgt_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgt_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgt_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgt_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtu_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtu_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtu_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtu_fp1_jump_t", 1);
	}

	static final Set<String> dot_new_predicates_operands;

	static {
		dot_new_predicates_operands = new HashSet<>();
		dot_new_predicates_operands.add("J2_jumptnew");
		dot_new_predicates_operands.add("J2_jumpfnew");
		dot_new_predicates_operands.add("J2_jumptnewpt");
		dot_new_predicates_operands.add("J2_jumpfnewpt");
		dot_new_predicates_operands.add("J2_jumprtnew");
		dot_new_predicates_operands.add("J2_jumprfnew");
		dot_new_predicates_operands.add("J2_jumprtnewpt");
		dot_new_predicates_operands.add("J2_jumprfnewpt");
		dot_new_predicates_operands.add("L4_return_tnew_pt");
		dot_new_predicates_operands.add("L4_return_fnew_pt");
		dot_new_predicates_operands.add("L4_return_tnew_pnt");
		dot_new_predicates_operands.add("L4_return_fnew_pnt");
		dot_new_predicates_operands.add("L2_ploadrubtnew_io");
		dot_new_predicates_operands.add("L2_ploadrubfnew_io");
		dot_new_predicates_operands.add("L4_ploadrubtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrubfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrubtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrubfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrubtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrubfnew_abs");
		dot_new_predicates_operands.add("L2_ploadrbtnew_io");
		dot_new_predicates_operands.add("L2_ploadrbfnew_io");
		dot_new_predicates_operands.add("L4_ploadrbtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrbfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrbtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrbfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrbtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrbfnew_abs");
		dot_new_predicates_operands.add("L2_ploadruhtnew_io");
		dot_new_predicates_operands.add("L2_ploadruhfnew_io");
		dot_new_predicates_operands.add("L4_ploadruhtnew_rr");
		dot_new_predicates_operands.add("L4_ploadruhfnew_rr");
		dot_new_predicates_operands.add("L2_ploadruhtnew_pi");
		dot_new_predicates_operands.add("L2_ploadruhfnew_pi");
		dot_new_predicates_operands.add("L4_ploadruhtnew_abs");
		dot_new_predicates_operands.add("L4_ploadruhfnew_abs");
		dot_new_predicates_operands.add("L2_ploadrhtnew_io");
		dot_new_predicates_operands.add("L2_ploadrhfnew_io");
		dot_new_predicates_operands.add("L4_ploadrhtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrhfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrhtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrhfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrhtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrhfnew_abs");
		dot_new_predicates_operands.add("L2_ploadritnew_io");
		dot_new_predicates_operands.add("L2_ploadrifnew_io");
		dot_new_predicates_operands.add("L4_ploadritnew_rr");
		dot_new_predicates_operands.add("L4_ploadrifnew_rr");
		dot_new_predicates_operands.add("L2_ploadritnew_pi");
		dot_new_predicates_operands.add("L2_ploadrifnew_pi");
		dot_new_predicates_operands.add("L4_ploadritnew_abs");
		dot_new_predicates_operands.add("L4_ploadrifnew_abs");
		dot_new_predicates_operands.add("L2_ploadrdtnew_io");
		dot_new_predicates_operands.add("L2_ploadrdfnew_io");
		dot_new_predicates_operands.add("L4_ploadrdtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrdfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrdtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrdfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrdtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrdfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbtnew_io");
		dot_new_predicates_operands.add("S4_pstorerbfnew_io");
		dot_new_predicates_operands.add("S4_pstorerbtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerbfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerbtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerbfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerbtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhtnew_io");
		dot_new_predicates_operands.add("S4_pstorerhfnew_io");
		dot_new_predicates_operands.add("S4_pstorerhtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerhfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerhtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerhfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerhtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerftnew_io");
		dot_new_predicates_operands.add("S4_pstorerffnew_io");
		dot_new_predicates_operands.add("S4_pstorerftnew_rr");
		dot_new_predicates_operands.add("S4_pstorerffnew_rr");
		dot_new_predicates_operands.add("S2_pstorerftnew_pi");
		dot_new_predicates_operands.add("S2_pstorerffnew_pi");
		dot_new_predicates_operands.add("S4_pstorerftnew_abs");
		dot_new_predicates_operands.add("S4_pstorerffnew_abs");
		dot_new_predicates_operands.add("S4_pstoreritnew_io");
		dot_new_predicates_operands.add("S4_pstorerifnew_io");
		dot_new_predicates_operands.add("S4_pstoreritnew_rr");
		dot_new_predicates_operands.add("S4_pstorerifnew_rr");
		dot_new_predicates_operands.add("S2_pstoreritnew_pi");
		dot_new_predicates_operands.add("S2_pstorerifnew_pi");
		dot_new_predicates_operands.add("S4_pstoreritnew_abs");
		dot_new_predicates_operands.add("S4_pstorerifnew_abs");
		dot_new_predicates_operands.add("S4_pstorerdtnew_io");
		dot_new_predicates_operands.add("S4_pstorerdfnew_io");
		dot_new_predicates_operands.add("S4_pstorerdtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerdfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerdtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerdfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerdtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerdfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerinewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerinewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerbnewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerbnewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerhnewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerhnewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_abs");
		dot_new_predicates_operands.add("S4_storeirbtnew_io");
		dot_new_predicates_operands.add("S4_storeirbfnew_io");
		dot_new_predicates_operands.add("S4_storeirhtnew_io");
		dot_new_predicates_operands.add("S4_storeirhfnew_io");
		dot_new_predicates_operands.add("S4_storeiritnew_io");
		dot_new_predicates_operands.add("S4_storeirifnew_io");
		dot_new_predicates_operands.add("C2_cmovenewit");
		dot_new_predicates_operands.add("C2_cmovenewif");
		dot_new_predicates_operands.add("C2_ccombinewnewt");
		dot_new_predicates_operands.add("C2_ccombinewnewf");
		dot_new_predicates_operands.add("A2_paddtnew");
		dot_new_predicates_operands.add("A2_paddfnew");
		dot_new_predicates_operands.add("A2_psubtnew");
		dot_new_predicates_operands.add("A2_psubfnew");
		dot_new_predicates_operands.add("A2_padditnew");
		dot_new_predicates_operands.add("A2_paddifnew");
		dot_new_predicates_operands.add("A2_pxortnew");
		dot_new_predicates_operands.add("A2_pxorfnew");
		dot_new_predicates_operands.add("A2_pandtnew");
		dot_new_predicates_operands.add("A2_pandfnew");
		dot_new_predicates_operands.add("A2_portnew");
		dot_new_predicates_operands.add("A2_porfnew");
		dot_new_predicates_operands.add("A4_psxtbtnew");
		dot_new_predicates_operands.add("A4_psxtbfnew");
		dot_new_predicates_operands.add("A4_pzxtbtnew");
		dot_new_predicates_operands.add("A4_pzxtbfnew");
		dot_new_predicates_operands.add("A4_psxthtnew");
		dot_new_predicates_operands.add("A4_psxthfnew");
		dot_new_predicates_operands.add("A4_pzxthtnew");
		dot_new_predicates_operands.add("A4_pzxthfnew");
		dot_new_predicates_operands.add("A4_paslhtnew");
		dot_new_predicates_operands.add("A4_paslhfnew");
		dot_new_predicates_operands.add("A4_pasrhtnew");
		dot_new_predicates_operands.add("A4_pasrhfnew");
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
		if (dot_new_predicates.containsKey(instr.getMnemonicString())
				|| dot_new_predicates_operands.contains(instr.getMnemonicString())) {
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
			boolean part1 = false;
			Instruction instr = insnIter.next();
			if (doesInstructionContainDotNewPredicate(instr)) {
				instructionsContainingDotNewPredicates.add(instr);
				if (isNewCmpJumpInstruction(instr)) {
					// resolve pcode for "part1" of new-comp jump instruction (the compare portion)
					part1 = true;
				} else {
					// don't resolve this until a later phase
					continue;
				}
			}

			final_pcode.addAll(fixupPcode(instr, part1, false));
		}
	}

	void processInstructionsContainingDotNewPredicates() throws UnknownInstructionException {
		for (Instruction instr : instructionsContainingDotNewPredicates) {
			// resolve pcode for "part2" of new-comp jump instruction (the new-jump portion)
			final_pcode.addAll(fixupPcode(instr, false, true));
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

	Set<Varnode> autoAndPredicatesWritten;

	List<PcodeOp> fixupPcode(Instruction instr, boolean part1, boolean part2) throws UnknownInstructionException {
		InstructionPrototype proto;
		InstructionContext ctx;

		Instruction instr_or_part;

		if (isNewCmpJumpInstruction(instr) && (part1 || part2)) {
			//
			// set part1 or part2 context register so that the subsequent proto.getPcode()
			// yields only the compare- or dot-new-jump part of the newcmpjump instruction
			//
			try {
				ProcessorContext impl = new ProcessorContextImpl(program.getLanguage());
				impl.setValue(part1Register, BigInteger.valueOf(part1 ? 1 : 0));
				impl.setValue(part2Register, BigInteger.valueOf(part2 ? 1 : 0));
				proto = program.getLanguage().parse(instr.getInstructionContext().getMemBuffer(), impl, false);
				PseudoInstruction pi = new PseudoInstruction(program, instr.getAddress(), proto,
						instr.getInstructionContext().getMemBuffer(), impl);
				ctx = pi;
				instr_or_part = pi;
			} catch (ContextChangeException | InsufficientBytesException | AddressOverflowException e) {
				String msg = "Unexpected exception when trying to break out new-cmp jump into parts" + e;
				throw new UnknownInstructionException(msg);
			}
		} else {
			proto = instr.getPrototype();
			ctx = instr.getInstructionContext();
			instr_or_part = instr;
		}

		// We need a local register temp space for local writes before they are written
		// to the global register temp space; this is because some instruction pcode
		// (the semantics, not the instruction itself) write to the same register more
		// than once
		HexagonRegisterScratchSpace regTempSpaceLocalWrite = new HexagonRegisterScratchSpace(program, uniqueFactory);

		LinkedList<PcodeOp> ops = new LinkedList<>();

		// Copy out any RW registers from regTempSpace into regTempSpaceLocalWrite
		for (Varnode vn : getRegsWritten(instr_or_part)) {
			Varnode dst = regTempSpaceLocalWrite.getScratchVn(vn);
			Varnode src = regTempSpaceWrite.getScratchVn(vn);
			ops.add(Copy(dst, src));
		}
		int start = ops.size();

		// add the main pcode for the instruction and fix it all up
		ops.addAll(Arrays.asList(proto.getPcode(ctx, null, null)));
		for (int i = start; i < ops.size(); i++) {
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
						Varnode vn = op.getInput(j);
						Varnode replace;
						if (regWrittenInInstruction(instr_or_part, program.getRegister(vn))) {
							replace = regTempSpaceLocalWrite.getScratchVn(vn);
						} else {
							replace = regTempSpace.getScratchVn(vn);
						}
						op.setInput(replace, j);
					}
				}
				if (op.getOutput() != null && op.getOutput().isRegister()) {
					regsWrittenSoFar.add(op.getOutput());
					op.setOutput(regTempSpaceLocalWrite.getScratchVn(op.getOutput()));
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

		// write out all written registers back to regTempSpaceWrite
		for (Varnode vn : getRegsWritten(instr_or_part)) {
			Varnode dst = regTempSpaceWrite.getScratchVn(vn);
			Varnode src = regTempSpaceLocalWrite.getScratchVn(vn);
			if (isPredicateRegister(vn)) {
				// Section 6.1.3 in "Hexagon V66 Programmer’s Reference Manual"
				// > If multiple compare instructions in a packet write to the same
				// > predicate register, the result is the logical AND of the
				// > individual compare results
				if (autoAndPredicatesWritten.contains(vn)) {
					ops.add(And(dst, src));
				} else {
					ops.add(Copy(dst, src));
					autoAndPredicatesWritten.add(vn);
				}
			} else {
				ops.add(Copy(dst, src));
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

	UniqueAddressFactory uniqueFactory;

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

		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				context.getAddress(), false);
		if (pkt_next == null) {
			// not yet analyzed
			throw new UnknownInstructionException("Packet not yet analyzed");
		}

		minAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_start.longValue());
		defaultSeqno = new SequenceNumber(minAddr, 0);

		pktNext = program.getAddressFactory().getDefaultAddressSpace().getAddress(pkt_next.longValue());

		maxAddr = pktNext.subtract(1);

		packetSize = pkt_next.subtract(pkt_start).intValue();

		AddressSet addrSet = new AddressSet(minAddr, maxAddr);

		this.uniqueFactory = uniqueFactory;

		regTempSpace = new HexagonRegisterScratchSpace(program, uniqueFactory);
		regTempSpaceWrite = new HexagonRegisterScratchSpace(program, uniqueFactory);

		regsWrittenSoFar = new HashSet<>(); // debugging tool

		autoAndPredicatesWritten = new HashSet<>();

		final_pcode = new ArrayList<PcodeOp>();

		//
		// General strategy is similar to binja-hexagon
		//
		// 1. First, all registers used into the packet are spilled into temporaries in
		// either regTempSpace or regTempSpaceWrite
		//

		initializeTemporaryRegisters(program.getListing().getInstructions(addrSet, true));

		//
		// 2. All branches in the packet are recorded in the order they appear in the
		// packet. Record and initialize a "branch var" that records whether that branch
		// is taken
		//
		// Order of jumps in the packet is important, because this is the order
		// jumps are resolved in (e.g. if one branch is conditional, and the
		// other branch is unconditional, the jump in the earlier instruction is
		// taken
		//

		recordBranchesAndValidateImplementedPcode(program.getListing().getInstructions(addrSet, true), uniqueFactory);

		//
		// 3. Copy pcode for all instructions that don't contain dot-new predicates.
		// Replace all registers with their appropriate temporaries
		//
		// N.B. there is a class of instructions, newcmpjump instructions of the form
		//
		// P0 = cmp.eq(R18,#0x0); if (P0.new) jump:nt 1f
		//
		// Such instructions both read and write a predicate register. They must be
		// split into part1 (the compare part) and part2 (the dot-new jump part). The
		// compare part's pcode is copied in this step. The dot-new jump part is handled
		// below.
		//
		// This is required for two reasons. Instructions containing dot-new
		// predicates can be earlier in the packet than the corresponding store:
		//
		// { if (!P0.new) r0 = #41
		// P0 = cmp.eq(R18,#0x0); if (P0.new) jump:nt 1f }
		//
		// We need to handle all dot-new predicates after the rest of the instructions
		// in the packet
		//
		// auto-and predicates presents an additional challenge. This is also valid:
		//
		// { p0 = cmp.eq(r5, #7); if (p0.new) jump:nt 1f
		// p0 = cmp.eq(r6, #7) }
		//
		// p0 is written twice in the same packet, so it's value at the end of the
		// packet is boolean AND'd: (r5 == #7) && (r6 == #7). p0.new also receives this
		// value, despite occuring in the packet before the second store to p0.
		//
		// This requires us to split up newcmpjump instructions into the cmp and dot-new
		// parts, instead of simply processing them after all other instructions
		//
		// N.B. new-value operands do not have the problem stated above, because
		// new-value operands are encoded with a constant indicating a *previous*
		// instruction in the packet. So the new-value producer must come earlier in the
		// packet
		//
		// N.B. Auto-and predicates are supported
		//
		// N.B. Code assumes that there is at most one external branch in every
		// instruction, not including fallthrough. endloop01 is the only exception with
		// two external jumps. FIXME there is a subtle bug causing improper
		// decompilation somewhere with endloop01, see testHwLoop01 in
		// HexagonPacketTestDecompilation
		//
		// N.B. Emitted pcode respects flow overrides and handles them appropriately
		//

		processInstructionsBesidesDotNewPredicates(program.getListing().getInstructions(addrSet, true));

		//
		// 5. Copy pcode for all other instructions containing dot-new predicates,
		// including the dot-new jump parts (part2) of newcmpjump instructions
		//

		processInstructionsContainingDotNewPredicates();

		//
		// 6. Resolve all register stores
		//

		resolveAllStores();

		//
		// 7. Resolve the correct branch destination in priority of the order each
		// branch appears in the packet
		//

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
		return new PcodeOp(defaultSeqno, PcodeOp.BOOL_AND, new Varnode[] { dst, src }, dst);
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
