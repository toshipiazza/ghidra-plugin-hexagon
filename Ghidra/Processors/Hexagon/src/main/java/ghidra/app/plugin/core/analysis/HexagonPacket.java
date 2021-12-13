package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class HexagonPacket {

	Program program;
	HexagonAnalysisState state;
	boolean dirty;

	AddressSet addrSet;

	HexagonPacket(Program program, HexagonAnalysisState state) {
		this.program = program;
		this.state = state;
		this.addrSet = new AddressSet();
		this.dirty = false;
	}

	boolean isTerminated() {
		int curValue = state.getParseBits(getMaxAddress());
		return curValue == 0b00 || curValue == 0b11;
	}

	public void addInstructionToEndOfPacket(Instruction instr) {
		if (this.addrSet.getNumAddresses() > 0) {
			if (isTerminated()) {
				throw new IllegalArgumentException("Instruction appended to already-terminated packet");
			}
			if (getMaxAddress().add(4) != instr.getMinAddress()) {
				throw new IllegalArgumentException("Instruction appended to packet is not immediately after packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	public void addInstructionToBegOfPacket(Instruction instr) {
		if (this.addrSet.getNumAddresses() > 0) {
			if (getMinAddress().subtract(4) != instr.getMaxAddress()) {
				throw new IllegalArgumentException("Instruction prepended to packet is not immediately before packet");
			}
		}
		dirty = true;
		addrSet.add(instr.getMinAddress());
	}

	Address getMinAddress() {
		return this.addrSet.getMinAddress();
	}

	Address getMaxAddress() {
		return this.addrSet.getMaxAddress();
	}
	
	void disassemblePacket(TaskMonitor monitor) {
		if (addrSet.getNumAddresses() == 0) {
			throw new IllegalArgumentException("No instructions in packet");
		}

		if (!isTerminated()) {
			throw new IllegalArgumentException("Packet is not terminated");
		}

		if (!dirty) {
			return;
		}
		
		program.getListing().clearCodeUnits(getMinAddress(), getMaxAddress(), false);
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		dis.disassemble(addrSet, addrSet, false);
		dirty = false;
	}
}
