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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

class HexagonInstructionInfo {

	Address addr;
	int parseBits;
	boolean endPacket;
	boolean isDuplex;
	boolean isImmext;
	HexagonInstructionInfo.DuplexEncoding duplex1;
	HexagonInstructionInfo.DuplexEncoding duplex2;
	Register newValueOperandRegister;

	HexagonInstructionInfo(Program program, Instruction instr, Address packetStartAddress)
			throws MemoryAccessException, UnknownInstructionException {
		this.addr = instr.getAddress();
		endPacket = false;
		isDuplex = false;

		isImmext = instr.getMnemonicString().equals("A4_ext");

		if (instr.getLength() != 4) {
			// See comment in reallyDisassembleInstruction().
			// We cleared subinsn, so all "instructions" should be 4
			// bytes. Duplex instructions will appear as a 4-byte opaque
			// DUPLEX temporary instruction.
			throw new IllegalArgumentException("Duplex subinstruction not allowed in HexagonInstructionInfo");
		}

		BigInteger value = BigInteger.valueOf(((instr.getByte(1) & 0xc0) >> 6) & 0b011);
		parseBits = value.intValue();
		if (parseBits == 0b00) {
			// This is an end of packet, and a duplex instruction
			endPacket = true;
			isDuplex = true;

			int iclass1 = ((instr.getByte(1) & 0x20) >> 5) & 0b001;
			int iclass2 = ((instr.getByte(3) & 0xe0) >> 5) & 0b111;
			int iclass = (iclass2 << 1) | iclass1;
			switch (iclass) {
			case 0:
				duplex1 = DuplexEncoding.L1;
				duplex2 = DuplexEncoding.L1;
				break;
			case 1:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.L1;
				break;
			case 2:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.L2;
				break;
			case 3:
				duplex1 = DuplexEncoding.A;
				duplex2 = DuplexEncoding.A;
				break;
			case 4:
				duplex1 = DuplexEncoding.L1;
				duplex2 = DuplexEncoding.A;
				break;
			case 5:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.A;
				break;
			case 6:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.A;
				break;
			case 7:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.A;
				break;
			case 8:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.L1;
				break;
			case 9:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.L2;
				break;
			case 10:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.S1;
				break;
			case 11:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.S1;
				break;
			case 12:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.L1;
				break;
			case 13:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.L2;
				break;
			case 14:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.S2;
				break;
			default:
				assert false;
			}
		}
		if (parseBits == 0b11) {
			endPacket = true;
		}

		resolveNewValueOperand(program, instr, packetStartAddress);
	}

	Address getAddress() {
		return addr;
	}

	private BigInteger getNewValueOperand(Instruction instr) throws UnknownInstructionException {
		Integer idx = HexagonInstructionAttributeConstants.getNewValueOperandIdx(instr);
		if (idx != null) {
			Object[] obj = instr.getOpObjects(idx);
			assert obj.length == 1;
			Object obj2 = obj[0];
			if (!(obj2 instanceof Scalar)) {
				Msg.error(this, "New-value operand wasn't a scalar (" + instr + ")");
				throw new UnknownInstructionException("New-value operand wasn't an immediate as expected");
			}
			Scalar s = (Scalar) obj2;
			return s.getBigInteger();
		}
		return null;
	}

	private void resolveNewValueOperand(Program program, Instruction instr, Address packetStartAddress)
			throws UnknownInstructionException {
		newValueOperandRegister = null;

		// N.B. duplex sub-instructions still appear as one placeholder
		// DUPLEX 4-byte instruction.
		//
		// However, duplex sub-instructions do not have new-value operands
		// (not to be confused with dot-new predicates) so we can analyze
		// this here

		if (isDuplex) {
			return;
		}

		BigInteger idx = getNewValueOperand(instr);
		if (idx == null) {
			return;
		}

		if (idx.intValue() == 0) {
			throw new UnknownInstructionException("New-value operand value is 0");
		}

		if ((idx.intValue() & 0b1) != 0) {
			throw new UnknownInstructionException("First bit of new-value operand is not 0");
		}

		int idx2 = idx.intValue();
		idx2 = (idx2 >> 1) & 0b11;

		Address start = instr.getAddress();

		for (int i = 0; i < idx2; ++i) {
			start = start.subtract(4);

			if (start.compareTo(packetStartAddress) < 0) {
				throw new UnknownInstructionException(
						"Invalid packet has dot-new operand pointing before the beginning of the packet");
			}

			Instruction inst = program.getListing().getInstructionAt(start);
			if (inst == null) {
				throw new UnknownInstructionException();
			}

			if (inst.getLength() != 4) {
				// sanity check that the math we did above was kosher
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

		extractNewValueOperandRegister(inst);
	}

	private void extractNewValueOperandRegister(Instruction inst) throws UnknownInstructionException {
		Integer idx = HexagonInstructionAttributeConstants.getIdxOfNewValueProducer(inst);
		if (idx == null) {
			throw new UnknownInstructionException(
					"Instruction producer for new-value operand did not have suitable register");
		}

		Object[] obj = inst.getOpObjects(idx);
		assert obj.length == 1;
		Object obj2 = obj[0];
		if (!(obj2 instanceof Register)) {
			Msg.error(this, "New-value producer wasn't a register (" + inst + ")");
			throw new UnknownInstructionException("New-value producer wasn't a register as expected");
		}
		newValueOperandRegister = (Register) obj2;
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
}
