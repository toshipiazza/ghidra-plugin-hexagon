package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
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

		AddressIterator addresses = set.getAddresses(true);

		while (addresses.hasNext()) {
			monitor.checkCanceled();

			Address addr = addresses.next();

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

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);

		AddressIterator addresses = set.getAddresses(true);

		boolean modified = false;
		while (addresses.hasNext()) {
			Address addr = addresses.next();
			modified |= state.removePacketForAddress(addr);
		}
		return modified;
	}

}
