package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class HexagonPacketAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "Hexagon Packet Analyzer";
	private static final String DESCRIPTION = "Analyze Hexagon Instructions for packets.";

	private final static int NOTIFICATION_INTERVAL = 1024;

	public HexagonPacketAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	private AddressSetView removeUninitializedBlock(Program program, AddressSetView set) {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isInitialized() && block.isLoaded()) {
				continue;
			}
			AddressSet blocksSet = new AddressSet();
			blocksSet.addRange(block.getStart(), block.getEnd());
			set = set.subtract(blocksSet);
		}
		return set;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);

		set = removeUninitializedBlock(program, set);

		final long locationCount = set.getNumAddresses();
		if (locationCount > NOTIFICATION_INTERVAL) {
			monitor.initialize(locationCount);
		}

		AddressIterator addresses = set.getAddresses(true);

		int count = 0;

		while (addresses.hasNext()) {
			monitor.checkCanceled();

			Address addr = addresses.next();

			if (locationCount > NOTIFICATION_INTERVAL) {
				if ((count % NOTIFICATION_INTERVAL) == 0) {
					monitor.setMaximum(locationCount);
					monitor.setProgress(count);
				}
				count++;
			}

			if ((addr.getOffset() & 0x3) != 0) {
				continue;
			}

			Instruction instr = program.getListing().getInstructionAt(addr);

			if (instr == null) {
				continue;
			}

			state.addInstructionToPacketOrCreatePacket(instr, monitor);
		}

		state.disassembleDirtyPackets(monitor);

		return true;
	}

}
