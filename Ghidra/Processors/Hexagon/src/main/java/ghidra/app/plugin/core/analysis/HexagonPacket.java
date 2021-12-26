package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.HexagonAnalysisState.DuplexEncoding;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InstructionSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
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

	AddressSet addrSet;

	HexagonPacket(Program program, HexagonAnalysisState state) {
		this.program = program;
		this.state = state;
		addrSet = new AddressSet();
		dirty = false;

		pktStartRegister = program.getProgramContext().getRegister("pkt_start");
		pktNextRegister = program.getProgramContext().getRegister("pkt_next");
		subinsnRegister = program.getProgramContext().getRegister("subinsn");
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
			Msg.error(this, "Unexpected Exception", e);
		}

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
		sb.append(" } @ ");
		sb.append(addrSet.getMinAddress().toString());
		return sb.toString();
	}
}
