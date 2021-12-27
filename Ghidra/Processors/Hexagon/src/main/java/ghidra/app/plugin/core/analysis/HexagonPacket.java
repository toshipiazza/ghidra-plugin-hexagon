package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;
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
	Register endloopRegister;

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
		endloopRegister = program.getProgramContext().getRegister("endloop");
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

	Register resolveNewValueReg(Address addr) throws UnknownInstructionException {
		Instruction instr = program.getListing().getInstructionAt(addr);
		if (instr == null) {
			throw new UnknownInstructionException("Instruction in packet not defined");
		}
		BigInteger idx = getNewValueOperand(instr);
		if (idx == null) {
			return null;
		}

		if (idx.intValue() == 0) {
			throw new UnknownInstructionException("New-value operand value of 0 is reserved and undefined");
		}

		if (hasDuplex()) {
			// no duplex instructions have new-value operands
			if (instr.getMinAddress().equals(getMaxAddress().add(0))) {
				return null;
			}
			if (instr.getMinAddress().equals(getMaxAddress().add(2))) {
				return null;
			}
		}

		int idx2 = idx.intValue();
		idx2 = (idx2 >> 1) & 0b11;

		Address start = instr.getMinAddress();

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
				// “ahead” is defined here as the instruction encoded at a lower
				// memory address than the consumer instruction, not counting
				// empty slots or constant extenders.
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
				Register regtemp = (Register) obj;
				if (regtemp.getAddress().getSize() != 32) {
					// producer for new-value operand must be 32-bit register
					continue;
				}
				if (!regtemp.getName().startsWith("R")) {
					// producer for new-value operand must be a GPR
					continue;
				}
				reg = regtemp;
			}
		}

		if (reg == null) {
			throw new UnknownInstructionException(
					"Instruction cannot be used as the destination of a new-value operand");
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

	enum LoopEncoding {
		NotLastInLoop, LastInLoop0, LastInLoop1, LastInLoop0And1;

		int toInt() {
			int loopEncodingValue = 0;
			switch (this) {
			case NotLastInLoop:
				loopEncodingValue = 0;
				break;
			case LastInLoop0:
				loopEncodingValue = 1;
				break;
			case LastInLoop1:
				loopEncodingValue = 2;
				break;
			case LastInLoop0And1:
				loopEncodingValue = 3;
				break;
			}
			return loopEncodingValue;
		}
	}

	LoopEncoding getEndLoop() {
		if (!isTerminated()) {
			throw new IllegalArgumentException();
		}

		AddressIterator iter = addrSet.getAddresses(true);
		Address addr1 = iter.next();
		if (!iter.hasNext()) {
			return LoopEncoding.NotLastInLoop;
		}
		Address addr2 = iter.next();

		int parse1 = state.getParseBits(addr1);
		int parse2 = state.getParseBits(addr2);

		if (parse2 == 0b00) {
			// packet with duplex instruction cannot end loop
			return LoopEncoding.NotLastInLoop;
		}

		if (parse1 == 0b00 || parse1 == 0b11) {
			// ought to be unreachable because of checks above
			assert false;
		} else if (parse1 == 0b10) {
			if (parse2 == 0b01 || parse2 == 0b11) {
				return LoopEncoding.LastInLoop0;
			} else if (parse2 == 0b10) {
				return LoopEncoding.LastInLoop0And1;
			}
		} else if (parse1 == 0b01) {
			if (parse2 == 0b01 || parse2 == 0b11) {
				return LoopEncoding.NotLastInLoop;
			} else if (parse2 == 0b10) {
				return LoopEncoding.LastInLoop1;
			}
		}

		// unreachable
		System.out.println(toString());
		assert false;
		return LoopEncoding.NotLastInLoop;
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

		Map<Address, BigInteger> newRegFixups = new HashMap<>();
		// Do initial pass for opcode which have new-value operands
		// N.B. we can do this here because no duplex instruction have new-value
		// operands
		AddressIterator iter = getAddressIter();
		while (iter.hasNext()) {
			Address addr = iter.next();
			Register reg;
			try {
				reg = resolveNewValueReg(addr);
				if (reg != null) {
					newRegFixups.put(addr, reg.getAddress().getOffsetAsBigInteger().divide(BigInteger.valueOf(4)));
				}
			} catch (UnknownInstructionException e) {
				Msg.error(this,
						"Unexpected Exception, could not set context registers nor resolve instructions with new-reg operands",
						e);
			}
		}

		program.getListing().clearCodeUnits(getMinAddress(), getMaxAddress().add(2), true);

		AddressSet addrSet2 = new AddressSet();
		iter = addrSet.getAddresses(true);
		while (iter.hasNext()) {
			addrSet2.add(iter.next());
		}

		// set pkt_start and pkt_end, and resolve duplex instructions
		BigInteger pktStart = BigInteger.valueOf(getMinAddress().getOffset());
		BigInteger pktNext = BigInteger.valueOf(getMaxAddress().add(4).getOffset());
		try {
			program.getProgramContext().setValue(pktStartRegister, getMinAddress(), getMaxAddress(), pktStart);
			program.getProgramContext().setValue(pktNextRegister, getMinAddress(), getMaxAddress(), pktNext);

			if (hasDuplex()) {
				Address duplexLo = getMaxAddress().add(0);
				Address duplexHi = getMaxAddress().add(2);
				BigInteger lo = BigInteger.valueOf(state.duplexInsns.get(duplexLo).getValue());
				BigInteger hi = BigInteger.valueOf(state.duplexInsns.get(duplexHi).getValue());
				program.getProgramContext().setValue(subinsnRegister, duplexLo, duplexLo, lo);
				program.getProgramContext().setValue(subinsnRegister, duplexHi, duplexHi, hi);
				addrSet2.add(duplexHi); // disassemble the duplex as well
			} else {
				// N.B. duplex instructions can't terminate endloops
				LoopEncoding loopEncoding = getEndLoop();
				program.getProgramContext().setValue(endloopRegister, getMaxAddress(), getMaxAddress(),
						BigInteger.valueOf(loopEncoding.toInt()));
			}

			if (newRegFixups.size() > 0) {
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
			}

		} catch (ContextChangeException e) {
			Msg.error(this, "Unexpected Exception, could not set context registers nor resolve duplex instructions", e);
		}

		// disassemble packet again so the context reg changes stick
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		dis.disassemble(addrSet2, addrSet2, false);

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
		sb.append(" }");
		switch (getEndLoop()) {
		case NotLastInLoop:
			break;
		case LastInLoop0:
			sb.append(":endloop0");
			break;
		case LastInLoop1:
			sb.append(":endloop1");
			break;
		case LastInLoop0And1:
			sb.append(":endloop0:endloop1");
			break;
		}
		sb.append(" @ ");
		sb.append(addrSet.getMinAddress().toString());
		return sb.toString();
	}
}
