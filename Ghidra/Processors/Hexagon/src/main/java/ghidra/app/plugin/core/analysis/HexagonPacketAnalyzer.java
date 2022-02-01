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

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
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

	private final static String PROCESSOR_NAME = "hexagon";

	private Register subinsnRegister;
	private Register hasnewRegister;
	private Register dotnewRegister;
	private Register duplexNextRegister;
	private Register pktStartRegister;
	private Register pktNextRegister;
	private Register endloopRegister;

	public HexagonPacketAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));

		if (!canAnalyze) {
			return false;
		}

		subinsnRegister = program.getProgramContext().getRegister("subinsn");
		hasnewRegister = program.getProgramContext().getRegister("hasnew");
		dotnewRegister = program.getProgramContext().getRegister("dotnew");
		duplexNextRegister = program.getProgramContext().getRegister("duplex_next");
		pktStartRegister = program.getProgramContext().getRegister("pkt_start");
		pktNextRegister = program.getProgramContext().getRegister("pkt_next");
		endloopRegister = program.getProgramContext().getRegister("endloop");

		return true;
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

	Instruction reallyDisassembleInstruction(Program program, TaskMonitor monitor, Address addr)
			throws UnknownInstructionException {
		BigInteger subinsn_value = program.getProgramContext().getValue(subinsnRegister, addr, false);
		BigInteger hasnew_value = program.getProgramContext().getValue(hasnewRegister, addr, false);
		if ((subinsn_value == null || subinsn_value.intValue() == 0)
				&& (hasnew_value == null || hasnew_value.intValue() == 0)) {
			Instruction inst = program.getListing().getInstructionAt(addr);
			if (inst != null) {
				return inst;
			}
		} else {
			// This instruction was previously part of a packet
			//
			// The subinsn context register is problematic since it turns one
			// instruction (DUPLEX) into several constituent subinsn's
			//
			// Similarly the hasnew and dotnew context registers interfere with
			// packet analysis so these are unset too
			program.getListing().clearCodeUnits(addr, addr.add(2), true);
			// Now the register should be clear, and the next call to
			// disassemble() should disassemble as DUPLEX
		}

		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AddressSet disassembled = dis.disassemble(addr, null, false);
		if (!disassembled.contains(addr)) {
			// give up, the instruction couldn't be disassembled
			throw new UnknownInstructionException();
		}

		AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);

		Instruction inst = program.getListing().getInstructionAt(addr);
		if (inst == null) {
			// give up, the instruction couldn't be disassembled
			throw new UnknownInstructionException();
		}
		return inst;
	}

	HexagonPacketInfo identifyPacketAtAddress(Program program, TaskMonitor monitor, Address addr, Instruction instr) {
		BookmarkManager bookmarkMgr = program.getBookmarkManager();

		HexagonInstructionInfo info;

		try {
			info = new HexagonInstructionInfo(program, instr, addr);
		} catch (UnknownInstructionException | MemoryAccessException ex) {
			// first instruction was invalid, clear the instruction
			program.getListing().clearCodeUnits(addr, addr, true);
			bookmarkMgr.setBookmark(addr, BookmarkType.ERROR, "Bad Instruction", ex.getMessage());
			return null;
		}

		HexagonPacketInfo packetInfo = new HexagonPacketInfo(addr, info);

		try {
			while (!packetInfo.isTerminated()) {
				instr = reallyDisassembleInstruction(program, monitor, packetInfo.packetEndAddress);
				info = new HexagonInstructionInfo(program, instr, packetInfo.packetStartAddress);
				packetInfo.addInstruction(info);
			}
		} catch (UnknownInstructionException | MemoryAccessException ex) {
			packetInfo.clearPacket(program);
			bookmarkMgr.setBookmark(addr, BookmarkType.ERROR, "Bad Instruction", ex.getMessage());
			return null;
		}

		return packetInfo;
	}

	void finalizeInstructionContext(Program program, HexagonPacketInfo packet, TaskMonitor monitor)
			throws CancelledException {
		program.getListing().clearCodeUnits(packet.packetStartAddress, packet.packetEndAddress.subtract(1), true);

		AddressSet disassembleSet = packet.getAddressSet();

		// cleanup error bookmarks
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(disassembleSet, monitor);

		// convert from exclusive to inclusive range
		Address packetStart = packet.packetStartAddress;
		Address packetEnd = packet.packetEndAddress.subtract(1);

		BigInteger pktStartCtx = BigInteger.valueOf(packetStart.getOffset());
		BigInteger pktNextCtx = BigInteger.valueOf(packet.packetEndAddress.getOffset());

		try {
			program.getProgramContext().setValue(pktStartRegister, packetStart, packetEnd, pktStartCtx);
			program.getProgramContext().setValue(pktNextRegister, packetStart, packetEnd, pktNextCtx);

			if (packet.hasDuplex) {
				if (packet.insns.size() >= 2) {
					HexagonInstructionInfo info = packet.insns.get(packet.insns.size() - 2);
					if (info.isImmext) {
						// Teach A2_ext to apply the immext to the second duplex subinstruction
						program.getProgramContext().setValue(duplexNextRegister, info.getAddress(), info.getAddress(),
								packet.duplex2Address.getOffsetAsBigInteger());
					}
				}

				program.getProgramContext().setValue(subinsnRegister, packet.duplex1Address, packet.duplex1Address,
						BigInteger.valueOf(packet.duplex1.getValue()));
				program.getProgramContext().setValue(subinsnRegister, packet.duplex2Address, packet.duplex2Address,
						BigInteger.valueOf(packet.duplex2.getValue()));
			} else {
				// packets with duplex instructions cannot terminate loops
				program.getProgramContext().setValue(endloopRegister, packet.LastInsnAddress, packet.LastInsnAddress,
						BigInteger.valueOf(packet.loopEncoding.toInt()));
			}

			for (HexagonInstructionInfo info : packet.insns) {
				if (info.newValueOperandRegister != null) {
					program.getProgramContext().setValue(hasnewRegister, info.getAddress(), info.getAddress(),
							BigInteger.valueOf(1));
					// All R. regs are 4-bytes long, so divide by 4 to get the register number from
					// its address
					program.getProgramContext().setValue(dotnewRegister, info.getAddress(), info.getAddress(),
							info.newValueOperandRegister.getAddress().getOffsetAsBigInteger()
									.divide(BigInteger.valueOf(4)));
				}
			}
		} catch (ContextChangeException e) {
			Msg.error(this, "Unexpected exception " + e);
			packet.clearPacket(program); // cleanup context anyway just in case
			return;
		}

		try {
			// disassemble packet again so the context reg changes stick
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSetView disassembled = dis.disassemble(disassembleSet, null, false);

			AddressIterator iter = disassembleSet.getAddresses(true);
			while (iter.hasNext()) {
				Address a = iter.next();
				if (!disassembled.contains(a)) {
					// some instructions did not disassemble
					throw new UnknownInstructionException(
							"Instruction in packet failed to disassemble after context set");
				}
				Instruction instr = program.getListing().getInstructionAt(a);
				if (instr.getMnemonicString().equals("DUPLEX")) {
					// duplex instructions should no longer exist at this point
					throw new UnknownInstructionException(
							"(Unreachable) Packet still contains DUPLEX after context set");
				}
			}

			// determine and set fallthrough across the packet
			boolean packetFallsThrough = true;

			AddressSet addrSet = new AddressSet(packet.packetStartAddress, packet.packetEndAddress.subtract(1));
			InstructionIterator insnIter = program.getListing().getInstructions(addrSet, true);
			while (insnIter.hasNext()) {
				Instruction instr = insnIter.next();
				if (instr.getPrototype().getFallThrough(instr.getInstructionContext()) == null) {
					packetFallsThrough = false;
				}
			}

			// ParallelInstructionLanguageHelper requires that all instructions in a packet
			// fallthrough except potentially the last one
			insnIter = program.getListing().getInstructions(addrSet, true);
			while (insnIter.hasNext()) {
				Instruction instr = insnIter.next();

				if (insnIter.hasNext()) {
					instr.setFallThrough(instr.getAddress().add(instr.getLength()));
				} else {
					if (packetFallsThrough) {
						instr.setFallThrough(packet.packetEndAddress);
					} else {
						instr.setFallThrough(null);
					}
				}
			}

			AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembled);

		} catch (UnknownInstructionException e) {
			packet.clearPacket(program);
			bookmarkMgr.removeBookmarks(disassembleSet, monitor);
			bookmarkMgr.setBookmark(packet.packetStartAddress, BookmarkType.ERROR, "Bad Instruction", e.getMessage());
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

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

			Instruction inst = program.getListing().getInstructionAt(addr);
			if (inst == null) {
				continue;
			}

			if ((addr.getOffset() & ~3) != addr.getOffset()) {
				if (inst.getLength() != 2) {
					// user might have disassembled on a 2-byte boundary, which is invalid
					program.getListing().clearCodeUnits(addr, addr, true);
				}
				continue;
			}

			BigInteger pkt_start = program.getProgramContext().getValue(pktStartRegister, addr, false);
			if (pkt_start != null && pkt_start.intValue() != 0) {
				continue;
			}

			HexagonPacketInfo packet = identifyPacketAtAddress(program, monitor, addr, inst);

			if (packet == null) {
				continue;
			}

			finalizeInstructionContext(program, packet, monitor);
		}

		return true;
	}

}
