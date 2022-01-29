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

import ghidra.app.plugin.core.analysis.HexagonInstructionInfo.DuplexEncoding;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;

import java.util.*;

class HexagonPacketInfo {

	List<HexagonInstructionInfo> insns;
	Address packetStartAddress;
	Address packetEndAddress;
	Address LastInsnAddress;

	boolean terminated;

	boolean hasDuplex;
	Address duplex1Address;
	Address duplex2Address;
	DuplexEncoding duplex1;
	DuplexEncoding duplex2;

	LoopEncoding loopEncoding;

	HexagonPacketInfo(Address addr, HexagonInstructionInfo info) {
		insns = new ArrayList<>();
		packetStartAddress = addr;
		packetEndAddress = addr;
		LastInsnAddress = null;
		terminated = false;
		hasDuplex = false;
		loopEncoding = LoopEncoding.NotLastInLoop;
		try {
			addInstruction(info);
		} catch (UnknownInstructionException ex) {
			// addInstruction only fails when we've exceeded 4 words, which
			// cannot have happened here yet
			Msg.error(this, "Unexpected exception " + ex);
		}
	}

	public AddressSet getAddressSet() {
		AddressSet disassembleSet = new AddressSet();
		for (HexagonInstructionInfo info : insns) {
			disassembleSet.add(info.getAddress());
		}
		if (hasDuplex) {
			disassembleSet.add(duplex2Address);
		}
		return disassembleSet;
	}

	public void clearPacket(Program program) {
		program.getListing().clearCodeUnits(packetStartAddress, packetEndAddress.subtract(1), true);
	}

	public void addInstruction(HexagonInstructionInfo info) throws UnknownInstructionException {
		insns.add(info);

		if (terminated) {
			throw new IllegalArgumentException("Attempting to push to terminated packet");
		}

		if (info.endPacket) {
			terminated = true;
			if (info.isDuplex) {
				hasDuplex = true;
				duplex1Address = info.getAddress();
				duplex2Address = info.getAddress().add(2);
				duplex1 = info.duplex1;
				duplex2 = info.duplex2;
			}
			loopEncoding = getLoopEncoding();
		} else if (insns.size() == 4) {
			// Section 10.9
			// > All packets must contain four or fewer words
			throw new UnknownInstructionException("Unterminated packet contained too many instructions");
		}

		LastInsnAddress = info.getAddress();
		packetEndAddress = packetEndAddress.add(4);
	}

	private LoopEncoding getLoopEncoding() {
		if (!isTerminated()) {
			throw new IllegalArgumentException();
		}

		if (insns.size() < 2) {
			return LoopEncoding.NotLastInLoop;
		}

		if (hasDuplex) {
			// a packet with duplex instructions cannot end a loop
			return LoopEncoding.NotLastInLoop;
		}

		int parse1 = insns.get(0).parseBits;
		int parse2 = insns.get(1).parseBits;

		if (parse1 == 0b00 || parse1 == 0b11) {
			// ought to be unreachable because of the checks above
			throw new AssertionError();
		} else if (parse1 == 0b10) {
			if (parse2 == 0b01 || parse2 == 0b11) {
				return LoopEncoding.LastInLoop0;
			} else if (parse2 == 0b10) {
				return LoopEncoding.LastInLoop0And1;
			} else {
				// parse2 was 0b00 which ought to be unreachable because of the
				// checks above
				throw new AssertionError();
			}
		} else if (parse1 == 0b01) {
			if (parse2 == 0b01 || parse2 == 0b11) {
				return LoopEncoding.NotLastInLoop;
			} else if (parse2 == 0b10) {
				return LoopEncoding.LastInLoop1;
			} else {
				// parse2 was 0b00 which ought to be unreachable because of the
				// checks above
				throw new AssertionError();
			}
		}
		// trivially unreachable
		throw new AssertionError();
	}

	public boolean isTerminated() {
		return terminated;
	}

	enum LoopEncoding {
		NotLastInLoop, LastInLoop0, LastInLoop1, LastInLoop0And1;

		int toInt() {
			int loopEncodingValue = 0;
			switch (this) {
			case NotLastInLoop:
				loopEncodingValue = 0;
				break;
			case LastInLoop0:
				loopEncodingValue = 1;
				break;
			case LastInLoop1:
				loopEncodingValue = 2;
				break;
			case LastInLoop0And1:
				loopEncodingValue = 3;
				break;
			}
			return loopEncodingValue;
		}
	}

	static final Map<String, Integer> dot_new_predicates;

	static {
		dot_new_predicates = new HashMap<>();
		dot_new_predicates.put("J4_cmpeqi_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqi_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqi_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqi_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgti_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgti_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgti_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgti_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtui_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtui_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtui_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtui_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqn1_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqn1_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeqn1_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeqn1_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtn1_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtn1_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtn1_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtn1_fp0_jump_t", 0);
		dot_new_predicates.put("J4_tstbit0_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_tstbit0_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_tstbit0_tp0_jump_t", 0);
		dot_new_predicates.put("J4_tstbit0_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeq_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeq_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpeq_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpeq_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgt_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgt_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgt_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgt_fp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtu_tp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtu_fp0_jump_nt", 0);
		dot_new_predicates.put("J4_cmpgtu_tp0_jump_t", 0);
		dot_new_predicates.put("J4_cmpgtu_fp0_jump_t", 0);
		dot_new_predicates.put("SA1_clrtnew", 0);
		dot_new_predicates.put("SA1_clrfnew", 0);
		dot_new_predicates.put("SL2_return_tnew", 0);
		dot_new_predicates.put("SL2_return_fnew", 0);
		dot_new_predicates.put("SL2_jumpr31_tnew", 0);
		dot_new_predicates.put("SL2_jumpr31_fnew", 0);
		dot_new_predicates.put("J4_cmpeqi_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqi_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqi_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqi_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgti_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgti_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgti_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgti_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtui_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtui_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtui_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtui_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqn1_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqn1_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeqn1_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeqn1_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtn1_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtn1_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtn1_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtn1_fp1_jump_t", 1);
		dot_new_predicates.put("J4_tstbit0_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_tstbit0_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_tstbit0_tp1_jump_t", 1);
		dot_new_predicates.put("J4_tstbit0_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeq_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeq_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpeq_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpeq_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgt_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgt_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgt_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgt_fp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtu_tp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtu_fp1_jump_nt", 1);
		dot_new_predicates.put("J4_cmpgtu_tp1_jump_t", 1);
		dot_new_predicates.put("J4_cmpgtu_fp1_jump_t", 1);
	}

	static final Set<String> dot_new_predicates_operands;

	static {
		dot_new_predicates_operands = new HashSet<>();
		dot_new_predicates_operands.add("J2_jumptnew");
		dot_new_predicates_operands.add("J2_jumpfnew");
		dot_new_predicates_operands.add("J2_jumptnewpt");
		dot_new_predicates_operands.add("J2_jumpfnewpt");
		dot_new_predicates_operands.add("J2_jumprtnew");
		dot_new_predicates_operands.add("J2_jumprfnew");
		dot_new_predicates_operands.add("J2_jumprtnewpt");
		dot_new_predicates_operands.add("J2_jumprfnewpt");
		dot_new_predicates_operands.add("L4_return_tnew_pt");
		dot_new_predicates_operands.add("L4_return_fnew_pt");
		dot_new_predicates_operands.add("L4_return_tnew_pnt");
		dot_new_predicates_operands.add("L4_return_fnew_pnt");
		dot_new_predicates_operands.add("L2_ploadrubtnew_io");
		dot_new_predicates_operands.add("L2_ploadrubfnew_io");
		dot_new_predicates_operands.add("L4_ploadrubtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrubfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrubtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrubfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrubtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrubfnew_abs");
		dot_new_predicates_operands.add("L2_ploadrbtnew_io");
		dot_new_predicates_operands.add("L2_ploadrbfnew_io");
		dot_new_predicates_operands.add("L4_ploadrbtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrbfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrbtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrbfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrbtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrbfnew_abs");
		dot_new_predicates_operands.add("L2_ploadruhtnew_io");
		dot_new_predicates_operands.add("L2_ploadruhfnew_io");
		dot_new_predicates_operands.add("L4_ploadruhtnew_rr");
		dot_new_predicates_operands.add("L4_ploadruhfnew_rr");
		dot_new_predicates_operands.add("L2_ploadruhtnew_pi");
		dot_new_predicates_operands.add("L2_ploadruhfnew_pi");
		dot_new_predicates_operands.add("L4_ploadruhtnew_abs");
		dot_new_predicates_operands.add("L4_ploadruhfnew_abs");
		dot_new_predicates_operands.add("L2_ploadrhtnew_io");
		dot_new_predicates_operands.add("L2_ploadrhfnew_io");
		dot_new_predicates_operands.add("L4_ploadrhtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrhfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrhtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrhfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrhtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrhfnew_abs");
		dot_new_predicates_operands.add("L2_ploadritnew_io");
		dot_new_predicates_operands.add("L2_ploadrifnew_io");
		dot_new_predicates_operands.add("L4_ploadritnew_rr");
		dot_new_predicates_operands.add("L4_ploadrifnew_rr");
		dot_new_predicates_operands.add("L2_ploadritnew_pi");
		dot_new_predicates_operands.add("L2_ploadrifnew_pi");
		dot_new_predicates_operands.add("L4_ploadritnew_abs");
		dot_new_predicates_operands.add("L4_ploadrifnew_abs");
		dot_new_predicates_operands.add("L2_ploadrdtnew_io");
		dot_new_predicates_operands.add("L2_ploadrdfnew_io");
		dot_new_predicates_operands.add("L4_ploadrdtnew_rr");
		dot_new_predicates_operands.add("L4_ploadrdfnew_rr");
		dot_new_predicates_operands.add("L2_ploadrdtnew_pi");
		dot_new_predicates_operands.add("L2_ploadrdfnew_pi");
		dot_new_predicates_operands.add("L4_ploadrdtnew_abs");
		dot_new_predicates_operands.add("L4_ploadrdfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbtnew_io");
		dot_new_predicates_operands.add("S4_pstorerbfnew_io");
		dot_new_predicates_operands.add("S4_pstorerbtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerbfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerbtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerbfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerbtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhtnew_io");
		dot_new_predicates_operands.add("S4_pstorerhfnew_io");
		dot_new_predicates_operands.add("S4_pstorerhtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerhfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerhtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerhfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerhtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerftnew_io");
		dot_new_predicates_operands.add("S4_pstorerffnew_io");
		dot_new_predicates_operands.add("S4_pstorerftnew_rr");
		dot_new_predicates_operands.add("S4_pstorerffnew_rr");
		dot_new_predicates_operands.add("S2_pstorerftnew_pi");
		dot_new_predicates_operands.add("S2_pstorerffnew_pi");
		dot_new_predicates_operands.add("S4_pstorerftnew_abs");
		dot_new_predicates_operands.add("S4_pstorerffnew_abs");
		dot_new_predicates_operands.add("S4_pstoreritnew_io");
		dot_new_predicates_operands.add("S4_pstorerifnew_io");
		dot_new_predicates_operands.add("S4_pstoreritnew_rr");
		dot_new_predicates_operands.add("S4_pstorerifnew_rr");
		dot_new_predicates_operands.add("S2_pstoreritnew_pi");
		dot_new_predicates_operands.add("S2_pstorerifnew_pi");
		dot_new_predicates_operands.add("S4_pstoreritnew_abs");
		dot_new_predicates_operands.add("S4_pstorerifnew_abs");
		dot_new_predicates_operands.add("S4_pstorerdtnew_io");
		dot_new_predicates_operands.add("S4_pstorerdfnew_io");
		dot_new_predicates_operands.add("S4_pstorerdtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerdfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerdtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerdfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerdtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerdfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerinewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerinewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerinewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerinewfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerbnewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerbnewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerbnewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerbnewfnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_io");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_io");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_rr");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_rr");
		dot_new_predicates_operands.add("S2_pstorerhnewtnew_pi");
		dot_new_predicates_operands.add("S2_pstorerhnewfnew_pi");
		dot_new_predicates_operands.add("S4_pstorerhnewtnew_abs");
		dot_new_predicates_operands.add("S4_pstorerhnewfnew_abs");
		dot_new_predicates_operands.add("S4_storeirbtnew_io");
		dot_new_predicates_operands.add("S4_storeirbfnew_io");
		dot_new_predicates_operands.add("S4_storeirhtnew_io");
		dot_new_predicates_operands.add("S4_storeirhfnew_io");
		dot_new_predicates_operands.add("S4_storeiritnew_io");
		dot_new_predicates_operands.add("S4_storeirifnew_io");
		dot_new_predicates_operands.add("C2_cmovenewit");
		dot_new_predicates_operands.add("C2_cmovenewif");
		dot_new_predicates_operands.add("C2_ccombinewnewt");
		dot_new_predicates_operands.add("C2_ccombinewnewf");
		dot_new_predicates_operands.add("A2_paddtnew");
		dot_new_predicates_operands.add("A2_paddfnew");
		dot_new_predicates_operands.add("A2_psubtnew");
		dot_new_predicates_operands.add("A2_psubfnew");
		dot_new_predicates_operands.add("A2_padditnew");
		dot_new_predicates_operands.add("A2_paddifnew");
		dot_new_predicates_operands.add("A2_pxortnew");
		dot_new_predicates_operands.add("A2_pxorfnew");
		dot_new_predicates_operands.add("A2_pandtnew");
		dot_new_predicates_operands.add("A2_pandfnew");
		dot_new_predicates_operands.add("A2_portnew");
		dot_new_predicates_operands.add("A2_porfnew");
		dot_new_predicates_operands.add("A4_psxtbtnew");
		dot_new_predicates_operands.add("A4_psxtbfnew");
		dot_new_predicates_operands.add("A4_pzxtbtnew");
		dot_new_predicates_operands.add("A4_pzxtbfnew");
		dot_new_predicates_operands.add("A4_psxthtnew");
		dot_new_predicates_operands.add("A4_psxthfnew");
		dot_new_predicates_operands.add("A4_pzxthtnew");
		dot_new_predicates_operands.add("A4_pzxthfnew");
		dot_new_predicates_operands.add("A4_paslhtnew");
		dot_new_predicates_operands.add("A4_paslhfnew");
		dot_new_predicates_operands.add("A4_pasrhtnew");
		dot_new_predicates_operands.add("A4_pasrhfnew");
	}

	static final Set<String> auto_and_predicates;

	static {
		auto_and_predicates = new HashSet<>();
		auto_and_predicates.add("C2_cmpeq");
		auto_and_predicates.add("C2_cmpgt");
		auto_and_predicates.add("C2_cmpgtu");
		auto_and_predicates.add("C2_cmpeqp");
		auto_and_predicates.add("C2_cmpgtp");
		auto_and_predicates.add("C2_cmpgtup");
		auto_and_predicates.add("C2_cmpeqi");
		auto_and_predicates.add("C2_cmpgti");
		auto_and_predicates.add("C2_cmpgtui");
		auto_and_predicates.add("A4_cmpbeq");
		auto_and_predicates.add("A4_cmpbeqi");
		auto_and_predicates.add("A4_cmpbgtu");
		auto_and_predicates.add("A4_cmpbgtui");
		auto_and_predicates.add("A4_cmpbgt");
		auto_and_predicates.add("A4_cmpbgti");
		auto_and_predicates.add("A4_cmpheq");
		auto_and_predicates.add("A4_cmphgt");
		auto_and_predicates.add("A4_cmphgtu");
		auto_and_predicates.add("A4_cmpheqi");
		auto_and_predicates.add("A4_cmphgti");
		auto_and_predicates.add("A4_cmphgtui");
		auto_and_predicates.add("J4_cmpeqi_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpeqi_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpeqi_tp0_jump_t");
		auto_and_predicates.add("J4_cmpeqi_fp0_jump_t");
		auto_and_predicates.add("J4_cmpeqi_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpeqi_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpeqi_tp1_jump_t");
		auto_and_predicates.add("J4_cmpeqi_fp1_jump_t");
		auto_and_predicates.add("J4_cmpgti_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpgti_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpgti_tp0_jump_t");
		auto_and_predicates.add("J4_cmpgti_fp0_jump_t");
		auto_and_predicates.add("J4_cmpgti_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpgti_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpgti_tp1_jump_t");
		auto_and_predicates.add("J4_cmpgti_fp1_jump_t");
		auto_and_predicates.add("J4_cmpgtui_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtui_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtui_tp0_jump_t");
		auto_and_predicates.add("J4_cmpgtui_fp0_jump_t");
		auto_and_predicates.add("J4_cmpgtui_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtui_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtui_tp1_jump_t");
		auto_and_predicates.add("J4_cmpgtui_fp1_jump_t");
		auto_and_predicates.add("J4_cmpeqn1_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpeqn1_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpeqn1_tp0_jump_t");
		auto_and_predicates.add("J4_cmpeqn1_fp0_jump_t");
		auto_and_predicates.add("J4_cmpeqn1_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpeqn1_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpeqn1_tp1_jump_t");
		auto_and_predicates.add("J4_cmpeqn1_fp1_jump_t");
		auto_and_predicates.add("J4_cmpgtn1_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtn1_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtn1_tp0_jump_t");
		auto_and_predicates.add("J4_cmpgtn1_fp0_jump_t");
		auto_and_predicates.add("J4_cmpgtn1_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtn1_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtn1_tp1_jump_t");
		auto_and_predicates.add("J4_cmpgtn1_fp1_jump_t");
		auto_and_predicates.add("J4_cmpeq_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpeq_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpeq_tp0_jump_t");
		auto_and_predicates.add("J4_cmpeq_fp0_jump_t");
		auto_and_predicates.add("J4_cmpeq_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpeq_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpeq_tp1_jump_t");
		auto_and_predicates.add("J4_cmpeq_fp1_jump_t");
		auto_and_predicates.add("J4_cmpgt_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpgt_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpgt_tp0_jump_t");
		auto_and_predicates.add("J4_cmpgt_fp0_jump_t");
		auto_and_predicates.add("J4_cmpgt_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpgt_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpgt_tp1_jump_t");
		auto_and_predicates.add("J4_cmpgt_fp1_jump_t");
		auto_and_predicates.add("J4_cmpgtu_tp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtu_fp0_jump_nt");
		auto_and_predicates.add("J4_cmpgtu_tp0_jump_t");
		auto_and_predicates.add("J4_cmpgtu_fp0_jump_t");
		auto_and_predicates.add("J4_cmpgtu_tp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtu_fp1_jump_nt");
		auto_and_predicates.add("J4_cmpgtu_tp1_jump_t");
		auto_and_predicates.add("J4_cmpgtu_fp1_jump_t");
		auto_and_predicates.add("SA1_cmpeqi");
	}

	Register getDotNewPredicate(Program program, Instruction inst) {
		// some instructions reference fixed predicate registers
		Integer predicateNo = dot_new_predicates.get(inst.getMnemonicString());
		if (predicateNo != null) {
			return program.getRegister(program.getRegister("P0").getAddress().add(predicateNo), 1);
		}

		// the rest of the instructions with dot-new predicates have predicates
		// specified as operands
		if (dot_new_predicates_operands.contains(inst.getMnemonicString())) {
			return getPredRegRead(inst);
		}

		return null;
	}

	Varnode getPredVarWritten(Instruction instr) {
		Register reg = getPredRegWritten(instr);
		if (reg == null) {
			return null;
		}
		return new Varnode(reg.getAddress(), reg.getNumBytes());
	}

	Register getPredRegWritten(Instruction instr) {
		Register ret = null;
		for (Object obj : instr.getResultObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				if (reg.getNumBytes() == 1) {
					assert ret == null;
					ret = reg;
				}
			}
		}
		return ret;
	}

	Register getPredRegRead(Instruction instr) {
		Register ret = null;
		for (Object obj : instr.getInputObjects()) {
			if (obj instanceof Register) {
				Register reg = (Register) obj;
				if (reg.getNumBytes() == 1) {
					assert ret == null;
					ret = reg;
				}
			}
		}
		return ret;
	}

	public void validatePredicates(Program program, InstructionIterator iter) throws UnknownInstructionException {
		Set<Varnode> predsWritten = new HashSet<>();

		while (iter.hasNext()) {
			Instruction instr = iter.next();

			// Section 6.1.3 in "Hexagon V66 Programmer’s Reference Manual"
			// > If multiple compare instructions in a packet write to the same
			// > predicate register, the result is the logical AND of the
			// > individual compare results
			// This is NYI, but fail instead of showing incorrect decompilation
			if (auto_and_predicates.contains(instr.getMnemonicString())) {
				Varnode pred = getPredVarWritten(instr);
				if (pred != null) {
					if (predsWritten.contains(pred)) {
						throw new UnknownInstructionException("NYI: predicate register " + pred
								+ " written several times in same packet must have auto-and semantics");
					}
					predsWritten.add(pred);
				}
			}
		}
	}

}
