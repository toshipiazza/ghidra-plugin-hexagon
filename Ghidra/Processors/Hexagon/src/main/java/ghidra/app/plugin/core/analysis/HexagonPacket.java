package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.HexagonAnalysisState.DuplexEncoding;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

public class HexagonPacket {

	Program program;
	HexagonAnalysisState state;
	boolean dirty;

	Register pktStartRegister;
	Register pktNextRegister;
	Register subinsnRegister;
	Register dotnewRegister;
	Register hasnewRegister;

	AddressSet addrSet;

	static Map<String, Integer> dot_new_operands;
	static {
		dot_new_operands = new HashMap<>();
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgti_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgti_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgti_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgti_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_tstbit0_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_tstbit0_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_tstbit0_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_tstbit0_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeq_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeq_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgt_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgt_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmplt_t_jumpnv_t", Integer.valueOf(1));
		dot_new_operands.put("J4_cmplt_t_jumpnv_nt", Integer.valueOf(1));
		dot_new_operands.put("J4_cmpltu_t_jumpnv_t", Integer.valueOf(1));
		dot_new_operands.put("J4_cmpltu_t_jumpnv_nt", Integer.valueOf(1));
		dot_new_operands.put("J4_cmpeq_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpeq_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgt_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgt_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_t", Integer.valueOf(0));
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_nt", Integer.valueOf(0));
		dot_new_operands.put("J4_cmplt_f_jumpnv_t", Integer.valueOf(1));
		dot_new_operands.put("J4_cmplt_f_jumpnv_nt", Integer.valueOf(1));
		dot_new_operands.put("J4_cmpltu_f_jumpnv_t", Integer.valueOf(1));
		dot_new_operands.put("J4_cmpltu_f_jumpnv_nt", Integer.valueOf(1));
		dot_new_operands.put("S2_storerinew_io", Integer.valueOf(1));
		dot_new_operands.put("S2_storerinew_pi", Integer.valueOf(1));
		dot_new_operands.put("S4_storerinew_ap", Integer.valueOf(1));
		dot_new_operands.put("S2_storerinew_pr", Integer.valueOf(2));
		dot_new_operands.put("S4_storerinew_ur", Integer.valueOf(1));
		dot_new_operands.put("S2_storerinew_pbr", Integer.valueOf(2));
		dot_new_operands.put("S2_storerinew_pci", Integer.valueOf(2));
		dot_new_operands.put("S2_storerinew_pcr", Integer.valueOf(2));
		dot_new_operands.put("S2_storerbnew_io", Integer.valueOf(1));
		dot_new_operands.put("S2_storerbnew_pi", Integer.valueOf(1));
		dot_new_operands.put("S4_storerbnew_ap", Integer.valueOf(1));
		dot_new_operands.put("S2_storerbnew_pr", Integer.valueOf(2));
		dot_new_operands.put("S4_storerbnew_ur", Integer.valueOf(1));
		dot_new_operands.put("S2_storerbnew_pbr", Integer.valueOf(2));
		dot_new_operands.put("S2_storerbnew_pci", Integer.valueOf(2));
		dot_new_operands.put("S2_storerbnew_pcr", Integer.valueOf(2));
		dot_new_operands.put("S2_storerhnew_io", Integer.valueOf(1));
		dot_new_operands.put("S2_storerhnew_pi", Integer.valueOf(1));
		dot_new_operands.put("S4_storerhnew_ap", Integer.valueOf(1));
		dot_new_operands.put("S2_storerhnew_pr", Integer.valueOf(2));
		dot_new_operands.put("S4_storerhnew_ur", Integer.valueOf(1));
		dot_new_operands.put("S2_storerhnew_pbr", Integer.valueOf(2));
		dot_new_operands.put("S2_storerhnew_pci", Integer.valueOf(2));
		dot_new_operands.put("S2_storerhnew_pcr", Integer.valueOf(2));
		dot_new_operands.put("S4_storerinew_rr", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerinewt_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerinewt_pi", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerinewf_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerinewf_pi", Integer.valueOf(2));
		dot_new_operands.put("S4_pstorerinewt_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerinewf_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerinewt_abs", Integer.valueOf(1));
		dot_new_operands.put("S4_pstorerinewf_abs", Integer.valueOf(1));
		dot_new_operands.put("S4_storerbnew_rr", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerbnewt_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerbnewt_pi", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerbnewf_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerbnewf_pi", Integer.valueOf(2));
		dot_new_operands.put("S4_pstorerbnewt_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerbnewf_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerbnewt_abs", Integer.valueOf(1));
		dot_new_operands.put("S4_pstorerbnewf_abs", Integer.valueOf(1));
		dot_new_operands.put("S4_storerhnew_rr", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerhnewt_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerhnewt_pi", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerhnewf_io", Integer.valueOf(2));
		dot_new_operands.put("S2_pstorerhnewf_pi", Integer.valueOf(2));
		dot_new_operands.put("S4_pstorerhnewt_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerhnewf_rr", Integer.valueOf(3));
		dot_new_operands.put("S4_pstorerhnewt_abs", Integer.valueOf(1));
		dot_new_operands.put("S4_pstorerhnewf_abs", Integer.valueOf(1));
		dot_new_operands.put("S2_storerinewgp", Integer.valueOf(0));
		dot_new_operands.put("S2_storerbnewgp", Integer.valueOf(0));
		dot_new_operands.put("S2_storerhnewgp", Integer.valueOf(0));
	}

	HexagonPacket(Program program, HexagonAnalysisState state) {
		this.program = program;
		this.state = state;
		addrSet = new AddressSet();
		dirty = false;

		pktStartRegister = program.getProgramContext().getRegister("pkt_start");
		pktNextRegister = program.getProgramContext().getRegister("pkt_next");
		subinsnRegister = program.getProgramContext().getRegister("subinsn");
		dotnewRegister = program.getProgramContext().getRegister("dotnew");
		hasnewRegister = program.getProgramContext().getRegister("hasnew");
	}

	boolean isTerminated() {
		return state.endPacket(getMaxAddress());
	}

	boolean hasDuplex() {
		return state.hasDuplex(getMaxAddress());
	}

	public void addInstructionToEndOfPacket(Instruction instr) {
		if (addrSet.getNumAddresses() > 0) {
			if (isTerminated()) {
				throw new IllegalArgumentException("Instruction appended to already-terminated packet");
			}
			if (!getMaxAddress().add(4).equals(instr.getMinAddress())) {
				throw new IllegalArgumentException("Instruction appended to packet is not immediately after packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	public void addInstructionToBegOfPacket(Instruction instr) {
		if (addrSet.getNumAddresses() > 0) {
			if (!getMinAddress().subtract(4).equals(instr.getMaxAddress())) {
				throw new IllegalArgumentException("Instruction prepended to packet is not immediately before packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	AddressIterator getAddressIter() {
		return addrSet.getAddresses(true);
	}

	Address getMinAddress() {
		return addrSet.getMinAddress();
	}

	Address getMaxAddress() {
		return addrSet.getMaxAddress();
	}

	BigInteger getNewValueOperand(Instruction instr) {
		Integer idx = dot_new_operands.get(instr.getMnemonicString());
		if (idx != null) {
			Object[] obj = instr.getOpObjects(idx.intValue());
			assert obj.length == 1;
			Object obj2 = obj[0];
			assert obj2 instanceof Scalar;
			Scalar s = (Scalar) obj2;
			return s.getBigInteger();
		}
		return null;
	}

	Register resolveNewValueReg(Instruction instr) throws UnknownInstructionException {
		BigInteger idx = getNewValueOperand(instr);
		if (idx == null) {
			return null;
		}

		int idx2 = idx.intValue();
		idx2 = (idx2 >> 1) & 0b11;

		Address start;
		if (hasDuplex() && instr.getMinAddress().equals(getMaxAddress().add(2))) {
			start = getMaxAddress();
		} else {
			start = instr.getMinAddress();
		}

		for (int i = 0; i < idx2; ++i) {
			start = start.subtract(4);
			if (!containsAddress(start)) {
				throw new UnknownInstructionException(
						"Invalid packet has dot-new operand pointing before the beginning of packet");
			}
			Instruction inst = program.getListing().getInstructionAt(start);
			if (inst == null) {
				throw new UnknownInstructionException();
			}
			if (inst.getMnemonicString().equals("A4_ext")) {
				// 10.10 New-Value operands
				//
				// “ahead” is defined here as the instruction encoded at a lower memory address
				// than the
				// consumer instruction, not counting empty slots or constant extenders.
				start = start.subtract(4);
			}
		}

		Instruction inst = program.getListing().getInstructionAt(start);
		if (inst == null) {
			throw new UnknownInstructionException();
		}

		Register reg = null;
		Object[] resultObj = inst.getResultObjects();

		for (Object obj : resultObj) {
			if (obj instanceof Register) {
				if (reg != null) {
					throw new UnknownInstructionException("Instruction " + inst + " writes to at least two registers ("
							+ reg + ", " + (Register) obj);
				}
				reg = (Register) obj;
				if (reg.getAddress().getSize() != 32) {
					throw new UnknownInstructionException(
							"Instruction cannot be used as the destination of a new-value operand");
				}
				if (!reg.getName().startsWith("R")) {
					throw new UnknownInstructionException(
							"Instruction cannot be used as the destination of a new-value operand");
				}
			}
		}

		if (reg == null) {
			throw new UnknownInstructionException();
		}

		return reg;
	}

	List<Instruction> getInstructions() throws UnknownInstructionException {
		List<Instruction> rv = new ArrayList<>();
		AddressIterator iter = addrSet.getAddresses(true);
		while (iter.hasNext()) {
			Instruction instr = program.getListing().getInstructionAt(iter.next());
			if (instr == null) {
				throw new UnknownInstructionException("Instruction in packet not defined");
			}
			rv.add(instr);
		}
		if (hasDuplex()) {
			Instruction instr = program.getListing().getInstructionAt(getMaxAddress().add(2));
			if (instr == null) {
				throw new UnknownInstructionException("Instruction in packet not defined");
			}
			rv.add(instr);
		}
		return rv;
	}

	boolean containsAddress(Address address) {
		if (addrSet.contains(address)) {
			return true;
		}
		// address can be at most 2 past the end
		return isTerminated() && hasDuplex() && getMaxAddress().add(2).equals(address);
	}

	boolean hasEndLoop() {
		throw new NotYetImplementedException("NYI");
	}

	int getEndLoop() {
		throw new NotYetImplementedException("NYI");
	}

	void redoPacket(TaskMonitor monitor) {
		if (addrSet.getNumAddresses() == 0) {
			throw new IllegalArgumentException("No instructions in packet");
		}

		if (!isTerminated()) {
			throw new IllegalArgumentException("Packet is not terminated");
		}

		if (!dirty) {
			return;
		}

		program.getListing().clearCodeUnits(getMinAddress(), getMaxAddress().add(2), true);

		AddressSet addrSet2 = new AddressSet();
		AddressIterator iter = addrSet.getAddresses(true);
		while (iter.hasNext()) {
			addrSet2.add(iter.next());
		}

		boolean hasDuplex = hasDuplex();

		// set pkt_start and pkt_end, and resolve duplex instructions
		BigInteger pktStart = BigInteger.valueOf(getMinAddress().getOffset());
		BigInteger pktNext = BigInteger.valueOf(getMaxAddress().add(4).getOffset());
		try {
			program.getProgramContext().setValue(pktStartRegister, getMinAddress(), getMaxAddress(), pktStart);
			program.getProgramContext().setValue(pktNextRegister, getMinAddress(), getMaxAddress(), pktNext);

			if (hasDuplex) {
				Address duplexLo = getMaxAddress().add(0);
				Address duplexHi = getMaxAddress().add(2);
				BigInteger lo = BigInteger.valueOf(state.duplexInsns.get(duplexLo).getValue());
				BigInteger hi = BigInteger.valueOf(state.duplexInsns.get(duplexHi).getValue());
				program.getProgramContext().setValue(subinsnRegister, duplexLo, duplexLo, lo);
				program.getProgramContext().setValue(subinsnRegister, duplexHi, duplexHi, hi);
				addrSet2.add(duplexHi); // disassemble the duplex as well
			}
		} catch (ContextChangeException e) {
			Msg.error(this, "Unexpected Exception, could not set context registers nor resolve duplex instructions", e);
		}

		// disassemble packet again so the context reg changes stick
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		dis.disassemble(addrSet2, addrSet2, false);

		Map<Address, BigInteger> newRegFixups = new HashMap<>();
		// do a second pass over the instructions assuming duplex instructions have been
		// created
		try {
			for (Instruction insn : getInstructions()) {
				Register reg = resolveNewValueReg(insn);
				if (reg != null) {
					newRegFixups.put(insn.getAddress(),
							reg.getAddress().getOffsetAsBigInteger().divide(BigInteger.valueOf(4)));
				}
			}
		} catch (UnknownInstructionException e) {
			// if duplex instructions failed to parse (for example) we could hit
			// this, but don't bother continuing since the packet is malformed
			// anyway
			Msg.error(this, "Could not get instructions from invalid packets", e);
		}

		if (newRegFixups.size() > 0) {
			// re-analyze packet so new-value operands are picked up properly
			program.getListing().clearCodeUnits(getMinAddress(), getMaxAddress().add(2), true);

			for (Map.Entry<Address, BigInteger> ent : newRegFixups.entrySet()) {
				Address a = ent.getKey();
				BigInteger b = ent.getValue();

				try {
					program.getProgramContext().setValue(hasnewRegister, a, a, BigInteger.valueOf(1));
					program.getProgramContext().setValue(dotnewRegister, a, a, b);
				} catch (ContextChangeException e) {
					Msg.error(this,
							"Unexpected Exception, could not set context registers nor resolve instructions with new-reg operands",
							e);
				}
			}

			// disassemble instructions with new-value operands
			dis.disassemble(addrSet2, addrSet2, false);
		}

		dirty = false;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{ ");
		AddressIterator iter = addrSet.getAddresses(true);
		while (iter.hasNext()) {
			Instruction instr = program.getListing().getInstructionAt(iter.next());
			sb.append(instr.toString());
			if (iter.hasNext()) {
				sb.append(" ; ");
			}
		}
		if (isTerminated() && hasDuplex()) {
			Instruction duplex = program.getListing().getInstructionAt(getMaxAddress().add(2));
			if (duplex != null) {
				sb.append(" ; ");
				sb.append(duplex.toString());
			}
		}
		sb.append(" } @ ");
		sb.append(addrSet.getMinAddress().toString());
		return sb.toString();
	}
}
