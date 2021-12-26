package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.plugin.processors.sleigh.PcodeEmitPacked;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.exception.NotYetImplementedException;
import ghidra.util.task.TaskMonitor;

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
	Set<Address> endPackets;
	Map<Address, DuplexEncoding> duplexInsns;
	LinkedList<HexagonPacket> packets;
	Program program;

	public HexagonAnalysisState(Program program) {
		packets = new LinkedList<>();
		parseBits = new HashMap<>();
		endPackets = new HashSet<>();
		duplexInsns = new HashMap<>();
		this.program = program;

//		try {
//			SleighLanguageDescription description = (SleighLanguageDescription)program.getLanguage().getLanguageDescription();
//			File iset = new ResourceFile(description.getSlaFile().getParentFile(), "iset.json").getFile(true);
//		} catch (IOException e) {
//			Msg.error(this, "Unexpected Exception", e);
//		}
	}

	boolean endPacket(Address address) {
		return endPackets.contains(address);
	}

	boolean hasDuplex(Address address) {
		boolean ret = endPacket(address) && duplexInsns.containsKey(address);
		if (ret) {
			assert duplexInsns.containsKey(address.add(2));
		}
		return ret;
	}

	int getParseBits(Address addr) {
		BigInteger value = parseBits.get(addr);
		if (value == null) {
			throw new IllegalArgumentException("No parse bits identified for given instruction");
		}
		return value.intValue();
	}

	enum DuplexEncoding {
		A, L1, L2, S1, S2;

		int getValue() {
			switch (this) {
			case A:
				return 1;
			case L1:
				return 2;
			case L2:
				return 3;
			case S1:
				return 4;
			case S2:
				return 5;
			}
			assert false;
			return -1;
		}
	}

	void addInstructionToPacketOrCreatePacket(Instruction instr, TaskMonitor monitor) {
		Address minAddress = instr.getMinAddress();
		Address maxAddress = instr.getMaxAddress();

		if (findPacketForAddress(instr.getMinAddress()) != null) {
			return;
		}

		// parse out Parse and duplex iclass bits
		try {
			BigInteger value = BigInteger.valueOf(((instr.getByte(1) & 0xc0) >> 6) & 0b011);
			parseBits.put(minAddress, value);
			if (value.intValue() == 0b00) {
				// This is an end of packet, and a duplex instruction
				Address addrLo = minAddress.add(0);
				Address addrHi = minAddress.add(2); // duplex is 2 bytes

				endPackets.add(addrLo);

				int iclass1 = ((instr.getByte(1) & 0x20) >> 5) & 0b001;
				int iclass2 = ((instr.getByte(3) & 0xe0) >> 5) & 0b111;
				int iclass = (iclass2 << 1) | iclass1;
				switch (iclass) {
				case 0:
					duplexInsns.put(addrLo, DuplexEncoding.L1);
					duplexInsns.put(addrHi, DuplexEncoding.L1);
					break;
				case 1:
					duplexInsns.put(addrLo, DuplexEncoding.L2);
					duplexInsns.put(addrHi, DuplexEncoding.L1);
					break;
				case 2:
					duplexInsns.put(addrLo, DuplexEncoding.L2);
					duplexInsns.put(addrHi, DuplexEncoding.L2);
					break;
				case 3:
					duplexInsns.put(addrLo, DuplexEncoding.A);
					duplexInsns.put(addrHi, DuplexEncoding.A);
					break;
				case 4:
					duplexInsns.put(addrLo, DuplexEncoding.L1);
					duplexInsns.put(addrHi, DuplexEncoding.A);
					break;
				case 5:
					duplexInsns.put(addrLo, DuplexEncoding.L2);
					duplexInsns.put(addrHi, DuplexEncoding.A);
					break;
				case 6:
					duplexInsns.put(addrLo, DuplexEncoding.S1);
					duplexInsns.put(addrHi, DuplexEncoding.A);
					break;
				case 7:
					duplexInsns.put(addrLo, DuplexEncoding.S2);
					duplexInsns.put(addrHi, DuplexEncoding.A);
					break;
				case 8:
					duplexInsns.put(addrLo, DuplexEncoding.S1);
					duplexInsns.put(addrHi, DuplexEncoding.L1);
					break;
				case 9:
					duplexInsns.put(addrLo, DuplexEncoding.S1);
					duplexInsns.put(addrHi, DuplexEncoding.L2);
					break;
				case 10:
					duplexInsns.put(addrLo, DuplexEncoding.S1);
					duplexInsns.put(addrHi, DuplexEncoding.S1);
					break;
				case 11:
					duplexInsns.put(addrLo, DuplexEncoding.S2);
					duplexInsns.put(addrHi, DuplexEncoding.S1);
					break;
				case 12:
					duplexInsns.put(addrLo, DuplexEncoding.S2);
					duplexInsns.put(addrHi, DuplexEncoding.L1);
					break;
				case 13:
					duplexInsns.put(addrLo, DuplexEncoding.S2);
					duplexInsns.put(addrHi, DuplexEncoding.L2);
					break;
				case 14:
					duplexInsns.put(addrLo, DuplexEncoding.S2);
					duplexInsns.put(addrHi, DuplexEncoding.S2);
					break;
				default:
					assert false;
				}
			}
			if (value.intValue() == 0b11) {
				endPackets.add(minAddress);
			}
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
				Msg.warn(this, "Packet was not terminated");
				continue;
			}
			packet.redoPacket(monitor);
		}
	}

	HexagonPacket findPacketForAddress(Address address) {
		for (HexagonPacket packet : packets) {
			if (packet.containsAddress(address)) {
				return packet;
			}
		}
		return null;
	}

	boolean removePacketForAddress(Address address) {
		for (HexagonPacket packet : packets) {
			if (packet.containsAddress(address)) {

				AddressIterator iter = packet.getAddressIter();
				while (iter.hasNext()) {
					Address addr = iter.next();
					parseBits.remove(addr);
				}
				if (packet.hasDuplex()) {
					Address addr = packet.getMaxAddress();
					duplexInsns.remove(addr.add(0));
					duplexInsns.remove(addr.add(2));
				}
				packets.remove(packet);
				return true;
			}
		}
		return false;
	}

	public String getMnemonicPrefix(Instruction instr) {
		Address minAddress = instr.getMinAddress();
		HexagonPacket packet = findPacketForAddress(minAddress);
		if (packet == null) {
			// instruction wasn't analyzed yet in HexagonPacketAnalyzer
			return "";
		}
		if (packet.getMinAddress().equals(minAddress)) {
			return "";
		}
		return "||";
	}

	public boolean isEndOfParallelInstructionGroup(Instruction instruction) {
		Address minAddress = instruction.getMinAddress();
		HexagonPacket packet = findPacketForAddress(minAddress);
		if (packet == null) {
			// instruction wasn't analyzed yet in HexagonPacketAnalyzer
			return true;
		}
		if (!packet.isTerminated()) {
			return false;
		}

		int add;
		if (packet.hasDuplex()) {
			add = 2;
		} else {
			add = 0;
		}

		return packet.getMaxAddress().add(add).equals(minAddress);
	}

	List<HexagonPacket> getPackets() {
		return new ArrayList<>(packets);
	}

	Address getRegisterTemp(Address[] scratchRegUnique, Address addr) {
		return scratchRegUnique[(int) (addr.getOffset() / 4)].add(addr.getOffset() % 4);
	}

	boolean branchRequiresFixup(PcodeOp op) {
		if (op.getOpcode() == PcodeOp.CBRANCH || op.getOpcode() == PcodeOp.BRANCH) {
			// constant cbranches are pcode-relative and don't need to be fixed up
			return !op.getInput(0).isConstant();
		}
		return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND
				|| op.getOpcode() == PcodeOp.BRANCHIND || op.getOpcode() == PcodeOp.RETURN;
	}

	boolean isCall(PcodeOp op) {
		return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
	}

	void analyzePcode(Instruction instruction, PcodeOp[] pcode, UniqueAddressFactory uniqueFactory,
			Address[] scratchRegUnique, Set<Varnode> registerSpills, Map<SequenceNumber, Varnode> branches) {

		// identify all the registers which need to be spilled up top and control flow
		// to be patched
		for (PcodeOp op : pcode) {
			for (int i = 0; i < op.getNumInputs(); ++i) {
				Address addr = op.getInput(i).getAddress();
				if (addr.getAddressSpace().getName().equals("register")) {
					registerSpills.add(op.getInput(i));
				}
			}
			if (branchRequiresFixup(op)) {
				branches.put(op.getSeqnum(), new Varnode(uniqueFactory.getNextUniqueAddress(), 1));
			}
		}
	}

	void initBranches(Address address, List<PcodeOp> uniqPcode, Map<SequenceNumber, Varnode> branches,
			AddressFactory addressFactory) {
		final int SPILL_UNIQ = 0x42424000;

		int seqno = 0;
		for (Varnode branchVn : branches.values()) {
			Varnode[] in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(0), 1) };
			PcodeOp spill = new PcodeOp(address, SPILL_UNIQ + seqno++, PcodeOp.COPY, in, branchVn);
			uniqPcode.add(spill);
		}
	}

	void spillRegs(Address address, List<PcodeOp> uniqPcode, Address[] scratchRegUnique, Set<Varnode> registerSpills) {
		final int SPILL_UNIQ = 0x41414000;

		int seqno = 0;
		for (Varnode reg : registerSpills) {
			Address uniq = getRegisterTemp(scratchRegUnique, reg.getAddress());
			Varnode[] in = new Varnode[] { reg };
			Varnode out = new Varnode(uniq, reg.getSize());
			PcodeOp spill = new PcodeOp(address, SPILL_UNIQ + seqno++, PcodeOp.COPY, in, out);
			uniqPcode.add(spill);
		}

	}

	boolean hasInternalCof(PcodeOp[] pcode) {
		for (PcodeOp op : pcode) {
			if (op.getOpcode() == PcodeOp.CBRANCH && op.getInput(0).getAddress().isConstantAddress()) {
				return true;
			}
		}
		return false;
	}

	boolean isNewRegUserOp(PcodeOp op) {
		// (unique, 0x27800, 1) CALLOTHER (const, 0x0, 4) , (unique, 0x96805, 1)

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
		return true;
	}

	void writePcode(Instruction instruction, Address maxAddress, PcodeOp[] pcode, List<PcodeOp> mainPcode,
			List<PcodeOp> jumpPcode, UniqueAddressFactory uniqueFactory, Address[] scratchRegUnique,
			Set<Varnode> registerSpills, Map<SequenceNumber, Varnode> branches, AddressFactory addressFactory) {
		final int SPILL_UNIQ = 0x43434000;

		int seqno = 0;
		for (PcodeOp op : pcode) {
			PcodeOp opNew;
			if (isNewRegUserOp(op)) {
				// replace `tmp = CALLOTHER 0 reg` with `tmp = reg`
				opNew = new PcodeOp(op.getSeqnum(), PcodeOp.COPY, 1, op.getOutput());
				opNew.setInput(op.getInput(1), 0);
			} else {
				opNew = new PcodeOp(op.getSeqnum(), op.getOpcode(), op.getNumInputs(), op.getOutput());
				for (int i = 0; i < op.getNumInputs(); i++) {
					if (op.getInput(i).getAddress().getAddressSpace().getName().equals("register")) {
						Address uniq = getRegisterTemp(scratchRegUnique, op.getInput(i).getAddress());
						opNew.setInput(new Varnode(uniq, op.getInput(i).getSize()), i);
					} else {
						opNew.setInput(op.getInput(i), i);
					}
				}
			}
			if (branchRequiresFixup(opNew)) {
				Varnode branchVn = branches.get(op.getSeqnum());
				if (hasInternalCof(pcode)) {
					Varnode[] in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(1), 1) };
					PcodeOp spill = new PcodeOp(instruction.getMinAddress(), SPILL_UNIQ + seqno++, PcodeOp.COPY, in,
							branchVn);
					mainPcode.add(spill);

					int disp = 2;
					if (isCall(op)) {
						disp = 3;
					}

					in = new Varnode[] { new Varnode(addressFactory.getConstantAddress(disp), 1), branchVn };
					PcodeOp insn1 = new PcodeOp(maxAddress, SPILL_UNIQ + seqno++, PcodeOp.CBRANCH, in, null);
					jumpPcode.add(insn1);
				}

				jumpPcode.add(opNew);

				if (isCall(op)) {
					// jump to next instruction in case of a call, so we don't
					// potentially fallthrough to another jump
					Varnode[] in = new Varnode[] { new Varnode(maxAddress.add(4), 4) };
					PcodeOp insn2 = new PcodeOp(maxAddress, SPILL_UNIQ + seqno++, PcodeOp.BRANCH, in, null);
					jumpPcode.add(insn2);
				}
			} else {
				mainPcode.add(opNew);
			}
		}
	}

	void writeOffset(PackedBytes buf, long val) {
		while (val != 0) {
			int chunk = (int) (val & 0x3f);
			val >>>= 6;
			buf.write(chunk + 0x20);
		}
		buf.write(PcodeEmitPacked.end_tag);
	}

	void dump(PackedBytes buf, Address instrAddr, int opcode, Varnode[] in, int isize, Varnode out) {
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

	void writePackedBytes(HexagonPacket packet, List<PcodeOp> pcode, PackedBytes buf)
			throws UnknownInstructionException {
		long packetSize = packet.getMaxAddress().add(4).subtract(packet.getMinAddress());
		buf.write(PcodeEmitPacked.inst_tag);
		writeOffset(buf, packetSize);

		Address pktAddr = packet.getMinAddress();
		int spcindex = pktAddr.getAddressSpace().getUnique();
		buf.write(spcindex + 0x20);
		writeOffset(buf, pktAddr.getOffset());

		for (PcodeOp op : pcode) {
			dump(buf, packet.getMinAddress(), op.getOpcode(), op.getInputs(), op.getNumInputs(), op.getOutput());
		}

		buf.write(PcodeEmitPacked.end_tag);
	}

	public List<PcodeOp> getPcode(InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		HexagonPacket packet = findPacketForAddress(context.getAddress());
		if (packet == null) {
			throw new UnknownInstructionException("No packet found at address " + context.getAddress());
		}
		if (!packet.getMinAddress().equals(context.getAddress())) {
			throw new UnknownInstructionException("Attempting to get pcode from " + context.getAddress()
					+ " which lies in the middle of packet " + packet);
		}

		List<PcodeOp> uniqPcode = new ArrayList<>();
		List<PcodeOp> mainPcode = new ArrayList<>();
		List<PcodeOp> jumpPcode = new ArrayList<>();

		Set<Varnode> registerSpills = new HashSet<>();
		Map<SequenceNumber, Varnode> branches = new HashMap<>();

		// Registers R1R0 aliases with R1 and R0, so their scratch regs must too
		// 64 registers R0 to R31 and C0 to R31
		Address[] scratchRegUnique = new Address[] { null, null, null, null, null, null, null, null, null, null, null,
				null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
				null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
				null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null,
				null, null, };
		for (int i = 0; i < scratchRegUnique.length; i += 2) {
			Address uniq = uniqueFactory.getNextUniqueAddress();
			scratchRegUnique[i + 0] = uniq.add(0);
			scratchRegUnique[i + 1] = uniq.add(4);
		}

		for (Instruction instr : packet.getInstructions()) {
			PcodeOp[] pcode = instr.getPrototype().getPcode(instr.getInstructionContext(), null, uniqueFactory);
			analyzePcode(instr, pcode, uniqueFactory, scratchRegUnique, registerSpills, branches);
		}

		initBranches(packet.getMinAddress(), uniqPcode, branches, program.getAddressFactory());
		spillRegs(packet.getMinAddress(), uniqPcode, scratchRegUnique, registerSpills);

		for (Instruction instr : packet.getInstructions()) {
			PcodeOp[] pcode = instr.getPrototype().getPcode(instr.getInstructionContext(), null, uniqueFactory);
			writePcode(instr, packet.getMaxAddress(), pcode, mainPcode, jumpPcode, uniqueFactory, scratchRegUnique,
					registerSpills, branches, program.getAddressFactory());
		}

		List<PcodeOp> donePcode = new ArrayList<>();
		donePcode.addAll(uniqPcode);
		donePcode.addAll(mainPcode);
		donePcode.addAll(jumpPcode);

		return donePcode;
	}

	public PackedBytes getPcodePacked(InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		HexagonPacket packet = findPacketForAddress(context.getAddress());
		if (packet == null) {
			throw new UnknownInstructionException("No packet found at address " + context.getAddress());
		}

		List<PcodeOp> donePcode = getPcode(context, uniqueFactory);

		PackedBytes packed = new PackedBytes(100);
		writePackedBytes(packet, donePcode, packed);
		return packed;
	}
}
