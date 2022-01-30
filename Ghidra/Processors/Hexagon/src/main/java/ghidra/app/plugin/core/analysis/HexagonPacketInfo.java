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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.HexagonInstructionInfo.DuplexEncoding;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

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
}
