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

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

class HexagonInstructionInfo {
	private static final Map<String, Integer> dot_new_operands;

	static {
		dot_new_operands = new HashMap<>();
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgti_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgti_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgti_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgti_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_tstbit0_t_jumpnv_t", 0);
		dot_new_operands.put("J4_tstbit0_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_tstbit0_f_jumpnv_t", 0);
		dot_new_operands.put("J4_tstbit0_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeq_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeq_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgt_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgt_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmplt_t_jumpnv_t", 1);
		dot_new_operands.put("J4_cmplt_t_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpltu_t_jumpnv_t", 1);
		dot_new_operands.put("J4_cmpltu_t_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpeq_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeq_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgt_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgt_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmplt_f_jumpnv_t", 1);
		dot_new_operands.put("J4_cmplt_f_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpltu_f_jumpnv_t", 1);
		dot_new_operands.put("J4_cmpltu_f_jumpnv_nt", 1);
		dot_new_operands.put("S2_storerinew_io", 1);
		dot_new_operands.put("S2_storerinew_pi", 1);
		dot_new_operands.put("S4_storerinew_ap", 1);
		dot_new_operands.put("S2_storerinew_pr", 2);
		dot_new_operands.put("S4_storerinew_ur", 1);
		dot_new_operands.put("S2_storerinew_pbr", 2);
		dot_new_operands.put("S2_storerinew_pci", 2);
		dot_new_operands.put("S2_storerinew_pcr", 2);
		dot_new_operands.put("S2_storerbnew_io", 1);
		dot_new_operands.put("S2_storerbnew_pi", 1);
		dot_new_operands.put("S4_storerbnew_ap", 1);
		dot_new_operands.put("S2_storerbnew_pr", 2);
		dot_new_operands.put("S4_storerbnew_ur", 1);
		dot_new_operands.put("S2_storerbnew_pbr", 2);
		dot_new_operands.put("S2_storerbnew_pci", 2);
		dot_new_operands.put("S2_storerbnew_pcr", 2);
		dot_new_operands.put("S2_storerhnew_io", 1);
		dot_new_operands.put("S2_storerhnew_pi", 1);
		dot_new_operands.put("S4_storerhnew_ap", 1);
		dot_new_operands.put("S2_storerhnew_pr", 2);
		dot_new_operands.put("S4_storerhnew_ur", 1);
		dot_new_operands.put("S2_storerhnew_pbr", 2);
		dot_new_operands.put("S2_storerhnew_pci", 2);
		dot_new_operands.put("S2_storerhnew_pcr", 2);
		dot_new_operands.put("S4_storerinew_rr", 2);
		dot_new_operands.put("S2_pstorerinewt_io", 2);
		dot_new_operands.put("S2_pstorerinewt_pi", 2);
		dot_new_operands.put("S2_pstorerinewf_io", 2);
		dot_new_operands.put("S2_pstorerinewf_pi", 2);
		dot_new_operands.put("S4_pstorerinewt_rr", 3);
		dot_new_operands.put("S4_pstorerinewf_rr", 3);
		dot_new_operands.put("S4_pstorerinewt_abs", 1);
		dot_new_operands.put("S4_pstorerinewf_abs", 1);
		dot_new_operands.put("S4_storerbnew_rr", 2);
		dot_new_operands.put("S2_pstorerbnewt_io", 2);
		dot_new_operands.put("S2_pstorerbnewt_pi", 2);
		dot_new_operands.put("S2_pstorerbnewf_io", 2);
		dot_new_operands.put("S2_pstorerbnewf_pi", 2);
		dot_new_operands.put("S4_pstorerbnewt_rr", 3);
		dot_new_operands.put("S4_pstorerbnewf_rr", 3);
		dot_new_operands.put("S4_pstorerbnewt_abs", 1);
		dot_new_operands.put("S4_pstorerbnewf_abs", 1);
		dot_new_operands.put("S4_storerhnew_rr", 2);
		dot_new_operands.put("S2_pstorerhnewt_io", 2);
		dot_new_operands.put("S2_pstorerhnewt_pi", 2);
		dot_new_operands.put("S2_pstorerhnewf_io", 2);
		dot_new_operands.put("S2_pstorerhnewf_pi", 2);
		dot_new_operands.put("S4_pstorerhnewt_rr", 3);
		dot_new_operands.put("S4_pstorerhnewf_rr", 3);
		dot_new_operands.put("S4_pstorerhnewt_abs", 1);
		dot_new_operands.put("S4_pstorerhnewf_abs", 1);
		dot_new_operands.put("S2_storerinewgp", 0);
		dot_new_operands.put("S2_storerbnewgp", 0);
		dot_new_operands.put("S2_storerhnewgp", 0);
	}

	Address addr;
	Instruction instr;
	int parseBits;
	boolean endPacket;
	boolean isDuplex;
	HexagonInstructionInfo.DuplexEncoding duplex1;
	HexagonInstructionInfo.DuplexEncoding duplex2;
	Register newValueOperandRegister;

	HexagonInstructionInfo(Program program, Instruction instr, Address packetStartAddress)
			throws MemoryAccessException, UnknownInstructionException {
		this.instr = instr;
		this.addr = instr.getAddress();
		endPacket = false;
		isDuplex = false;

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

		resolveNewValueOperand(program, packetStartAddress);
	}

	public void debugPrint() {
		Msg.debug(this, "=== Debug info for instruction " + instr);
		Msg.debug(this, "- Parse bits: " + parseBits);
		if (newValueOperandRegister != null) {
			Msg.debug(this, "- Has new-value operand " + newValueOperandRegister.getName());
		}
		if (endPacket) {
			Msg.debug(this, "- Terminates packet");
			if (isDuplex) {
				Msg.debug(this, "- Packet is duplex");
				Msg.debug(this, "- duplex1 is type " + duplex1);
				Msg.debug(this, "- duplex2 is type " + duplex2);
			}
		}
	}

	Address getAddress() {
		return addr;
	}

	private BigInteger getNewValueOperand(Instruction instr) {
		Integer idx = dot_new_operands.get(instr.getMnemonicString());
		if (idx != null) {
			Object[] obj = instr.getOpObjects(idx);
			assert obj.length == 1;
			Object obj2 = obj[0];
			assert obj2 instanceof Scalar;
			Scalar s = (Scalar) obj2;
			return s.getBigInteger();
		}
		return null;
	}

	private void resolveNewValueOperand(Program program, Address packetStartAddress)
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
		Object[] resultObj = inst.getResultObjects();

		for (Object obj : resultObj) {
			if (obj instanceof Register) {
				if (newValueOperandRegister != null) {
					throw new UnknownInstructionException(
							"Instruction producer for new-value operand writes to at least two registers");
				}

				Register regtemp = (Register) obj;

				if (regtemp.getAddress().getSize() != 32) {
					// producer for the new-value operand must be 32-bit register
					continue;
				}
				if (!regtemp.getName().startsWith("R")) {
					// producer for the new-value operand must be R0-R31
					continue;
				}
				newValueOperandRegister = regtemp;
			}
		}

		if (newValueOperandRegister == null) {
			throw new UnknownInstructionException(
					"Instruction producer for new-value operand did not have suitable register");
		}
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
