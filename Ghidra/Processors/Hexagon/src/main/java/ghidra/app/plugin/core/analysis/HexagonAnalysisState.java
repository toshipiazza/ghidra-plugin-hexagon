package ghidra.app.plugin.core.analysis;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;

public class HexagonAnalysisState implements AnalysisState {

	public static synchronized HexagonAnalysisState getState(Program program) {
		HexagonAnalysisState analysisState = AnalysisStateInfo.getAnalysisState(program, HexagonAnalysisState.class);
		if (analysisState == null) {
			analysisState = new HexagonAnalysisState(program);
			AnalysisStateInfo.putAnalysisState(program, analysisState);
		}
		return analysisState;
	}

	Map<Address, BigInteger> parseBits;
	LinkedList<HexagonPacket> packets;
	Program program;

	public HexagonAnalysisState(Program program) {
		packets = new LinkedList<>();
		parseBits = new HashMap<>();
		this.program = program;
	}

	int getParseBits(Address addr) {
		BigInteger value = parseBits.get(addr);
		if (value == null) {
			throw new IllegalArgumentException("No parse bits identified for given instruction");
		}
		return value.intValue();
	}

	void addInstructionToPacketOrCreatePacket(Instruction instr, TaskMonitor monitor) {
		Address minAddress = instr.getMinAddress();
		Address maxAddress = instr.getMaxAddress();

		if (parseBits.containsKey(minAddress)) {
			// no need to reanalyze
			return;
		}

		// parse out Parse bits
		try {
			BigInteger value = BigInteger.valueOf(((instr.getByte(1) & 0xc0) >> 6) & 0b11);
			parseBits.put(minAddress, value);
		} catch (MemoryAccessException e) {
			Msg.error(this, "Unexpected Exception", e);
			return;
		}

		HexagonPacket newPacket = new HexagonPacket(program, this);
		newPacket.addInstructionToEndOfPacket(instr);

		// perform insertion sort for the instruction into the closest packet
		for (int i = 0; i < packets.size(); ++i) {
			HexagonPacket packet = packets.get(i);

			// instruction immediately precedes packet
			if (maxAddress.equals(packet.getMinAddress())) {
				if (newPacket.isTerminated()) {
					// create a new packet
					packets.add(i, newPacket);
					return;
				}
				packet.addInstructionToBegOfPacket(instr);
				return;
			}

			// instruction immediately succeeds packet
			if (minAddress.equals(packet.getMaxAddress().add(4))) {
				if (packet.isTerminated()) {
					// create a new packet
					packets.add(i + 1, newPacket);
					return;
				}
				packet.addInstructionToEndOfPacket(instr);
				return;
			}

			// packet succeeds instruction, so insert before
			if (packet.getMinAddress().compareTo(instr.getMinAddress()) == 1) {
				packets.add(i, newPacket);
				return;
			}
		}

		// either empty or packet needs to be added to the end
		packets.add(newPacket);
	}

	void disassembleDirtyPackets(TaskMonitor monitor) {
		for (HexagonPacket packet : packets) {
			if (!packet.isTerminated()) {
				//
				// Unterminated packet likely contains control flow that ghidra assumed
				// terminated the bb
				// Must set flow override and trigger reanalysis
				//
				Msg.info(this, "NYI -- unterminated packet");
				continue;
			}
			packet.disassemblePacket(monitor);
		}
	}

	void debugPrintAllKnownPackets() {
		for (HexagonPacket packet : packets) {
			Msg.info(this, packet);
		}
	}

	HexagonPacket findPacketForInstruction(Instruction instr) {
		Address address = instr.getMinAddress();
		for (HexagonPacket packet : packets) {
			if (packet.containsAddress(address)) {
				return packet;
			}
		}
		return null;
	}

	public String getMnemonicPrefix(Instruction instr) {
		Address minAddress = instr.getMinAddress();
		HexagonPacket packet = findPacketForInstruction(instr);
		if (packet == null) {
			// instruction wasn't analyzed yet in HexagonPacketAnalyzer
			return "";
		}
		if (packet.getMinAddress() == minAddress) {
			return "";
		}
		return "||";
	}

	public boolean isEndOfParallelInstructionGroup(Instruction instruction) {
		Address minAddress = instruction.getMinAddress();
		HexagonPacket packet = findPacketForInstruction(instruction);
		if (packet == null) {
			// instruction wasn't analyzed yet in HexagonPacketAnalyzer
			return true;
		}
		if (packet.getMaxAddress() == minAddress && packet.isTerminated()) {
			return true;
		}
		return false;
	}

	List<HexagonPacket> getPackets() {
		return new ArrayList<>(packets);
	}

}
