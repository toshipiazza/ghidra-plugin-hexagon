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
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;

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

	Instruction reallyDisassembleInstruction(Program program, TaskMonitor monitor, Address addr)
			throws UnknownInstructionException {
		BigInteger subinsn_value = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("subinsn"), addr, false);
		BigInteger hasnew_value = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("hasnew"), addr, false);
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

	HexagonPacketInfo identifyPacketAtAddress(Program program, TaskMonitor monitor, Address addr) {
		HexagonPacketInfo packetInfo = new HexagonPacketInfo(addr);
		try {
			do {
				Instruction inst = reallyDisassembleInstruction(program, monitor, packetInfo.packetEndAddress);

				HexagonInstructionInfo info = new HexagonInstructionInfo(program, inst, packetInfo.packetStartAddress);
				packetInfo.addInstruction(info);

			} while (!packetInfo.isTerminated());
		} catch (UnknownInstructionException | MemoryAccessException ex) {
			Msg.error(this, "Unable to parse full packet at address " + addr + ": " + ex);
			if (!packetInfo.packetStartAddress.equals(packetInfo.packetEndAddress)) {
				program.getListing().clearCodeUnits(packetInfo.packetStartAddress,
						packetInfo.packetEndAddress.subtract(1), true);
			} else {
				// an exception on the first instruction might cause this
				program.getListing().clearCodeUnits(packetInfo.packetStartAddress, packetInfo.packetEndAddress, true);
			}
			return null;
		}

		return packetInfo;
	}

	void finalizeInstructionContext(Program program, HexagonPacketInfo packet, TaskMonitor monitor)
			throws CancelledException {
		program.getListing().clearCodeUnits(packet.packetStartAddress, packet.packetEndAddress.subtract(1), true);

		AddressSet disassembleSet = new AddressSet();
		for (HexagonInstructionInfo info : packet.insns) {
			disassembleSet.add(info.getAddress());
		}
		if (packet.hasDuplex) {
			disassembleSet.add(packet.duplex2Address);
		}

		// cleanup error bookmarks
		BookmarkManager bookmarkMgr = program.getBookmarkManager();
		bookmarkMgr.removeBookmarks(disassembleSet, monitor);

		// convert from exclusive to inclusive range
		Address packetStart = packet.packetStartAddress;
		Address packetEnd = packet.packetEndAddress.subtract(1);

		BigInteger pktStartCtx = BigInteger.valueOf(packetStart.getOffset());
		BigInteger pktNextCtx = BigInteger.valueOf(packet.packetEndAddress.getOffset());

		try {
			program.getProgramContext().setValue(program.getProgramContext().getRegister("pkt_start"), packetStart,
					packetEnd, pktStartCtx);
			program.getProgramContext().setValue(program.getProgramContext().getRegister("pkt_next"), packetStart,
					packetEnd, pktNextCtx);

			if (packet.hasDuplex) {
				if (packet.insns.size() >= 2) {
					HexagonInstructionInfo info = packet.insns.get(packet.insns.size() - 2);
					if (info.isImmext) {
						// A2_ext needs to know the address of both duplex instructions if immext comes
						// just before
						program.getProgramContext().setValue(program.getProgramContext().getRegister("duplex_next"),
								info.getAddress(), info.getAddress(), packet.duplex2Address.getOffsetAsBigInteger());
					}
				}

				Register subinsnRegister = program.getProgramContext().getRegister("subinsn");
				program.getProgramContext().setValue(subinsnRegister, packet.duplex1Address, packet.duplex1Address,
						BigInteger.valueOf(packet.duplex1.getValue()));
				program.getProgramContext().setValue(subinsnRegister, packet.duplex2Address, packet.duplex2Address,
						BigInteger.valueOf(packet.duplex2.getValue()));
			} else {
				// packets with duplex instructions cannot terminate loops
				program.getProgramContext().setValue(program.getProgramContext().getRegister("endloop"),
						packet.LastInsnAddress, packet.LastInsnAddress,
						BigInteger.valueOf(packet.loopEncoding.toInt()));
			}

			for (HexagonInstructionInfo info : packet.insns) {
				if (info.newValueOperandRegister != null) {
					program.getProgramContext().setValue(program.getProgramContext().getRegister("hasnew"),
							info.getAddress(), info.getAddress(), BigInteger.valueOf(1));
					// All R. regs are 4-bytes long, so divide by 4 to get the register number from
					// its address
					program.getProgramContext().setValue(program.getProgramContext().getRegister("dotnew"),
							info.getAddress(), info.getAddress(), info.newValueOperandRegister.getAddress()
									.getOffsetAsBigInteger().divide(BigInteger.valueOf(4)));
				}
			}
		} catch (ContextChangeException e) {
			// undo everything, and ensure the packet had been cleared completely
			Msg.error(this,
					"Unable to finalize context registers for packet at @ " + packet.packetStartAddress + ": " + e);
			program.getListing().clearCodeUnits(packet.packetStartAddress, packet.packetEndAddress.subtract(1), true);
			return;
		}

		try {
			// disassemble packet again so the context reg changes stick
			Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
			AddressSetView disassembled = dis.disassemble(disassembleSet, null, true);

			AddressIterator iter = disassembleSet.getAddresses(true);
			while (iter.hasNext()) {
				Address a = iter.next();
				if (!disassembled.contains(a)) {
					// some instructions did not disassemble
					throw new UnknownInstructionException();
				}
				Instruction instr = program.getListing().getInstructionAt(a);
				if (instr.getMnemonicString().equals("DUPLEX")) {
					// duplex instructions should no longer exist at this point
					throw new UnknownInstructionException();
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
			Msg.error(this,
					"Packet failed to disassemble after finalizing context at " + packet.packetStartAddress + ": " + e);
			// undo everything, and ensure the packet had been cleared completely
			program.getListing().clearCodeUnits(packet.packetStartAddress, packet.packetEndAddress.subtract(1), true);
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

			if (program.getListing().getInstructionAt(addr) == null) {
				continue;
			}

			if ((addr.getOffset() & ~3) != addr.getOffset()) {
				Instruction inst = program.getListing().getInstructionAt(addr);
				if (inst != null) {
					if (inst.getLength() != 2) {
						// user might have disassembled on a 2-byte boundary, which is invalid
						program.getListing().clearCodeUnits(addr, addr, true);
					}
				}
				continue;
			}

			BigInteger pkt_start = program.getProgramContext()
					.getValue(program.getProgramContext().getRegister("pkt_start"), addr, false);
			if (pkt_start != null && pkt_start.intValue() != 0) {
				continue;
			}

			HexagonPacketInfo packet = identifyPacketAtAddress(program, monitor, addr);

			if (packet == null) {
				continue;
			}

			finalizeInstructionContext(program, packet, monitor);
		}

		return true;
	}

}
