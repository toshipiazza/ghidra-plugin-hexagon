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

import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import java.math.BigInteger;

public class HexagonParallelInstructionLanguageHelper implements ParallelInstructionLanguageHelper {

	@Override
	public String getMnemonicPrefix(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_start = program.getProgramContext()
				.getValue(program.getProgramContext().getRegister("pkt_start"), instr.getAddress(), false);
		if (pkt_start == null || pkt_start.intValue() == 0) {
			// not yet analyzed
			return null;
		}
		if (pkt_start.equals(instr.getAddress().getOffsetAsBigInteger())) {
			// start of packet
			return "{";
		}
		// middle of packet
		return null;
	}

	@Override
	public String getMnemonicSuffix(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				instr.getAddress(), false);
		if (pkt_next == null || pkt_next.intValue() == 0) {
			// not yet analyzed
			return null;
		}
		if (pkt_next.equals(instr.getAddress().add(instr.getLength()).getOffsetAsBigInteger())) {
			// end of packet
			String res = "}";

			BigInteger endloop = program.getProgramContext()
					.getValue(program.getProgramContext().getRegister("endloop"), instr.getAddress(), false);
			if (endloop != null) {
				// add applicable endloop suffix
				switch (endloop.intValue()) {
				case 0:
					break;
				case 1:
					res += ":endloop0";
					break;
				case 2:
					res += ":endloop1";
					break;
				case 3:
					res += ":endloop1:endloop0";
					break;
				}
			}

			return res;
		}
		// middle of packet
		return null;
	}

	@Override
	public boolean isEndOfParallelInstructionGroup(Instruction instr) {
		Program program = instr.getProgram();
		BigInteger pkt_next = program.getProgramContext().getValue(program.getProgramContext().getRegister("pkt_next"),
				instr.getAddress(), false);
		if (pkt_next == null) {
			// not yet analyzed
			return false;
		}
		// instr is not the last instruction in the packet
		return instr.getMaxAddress().add(1).getOffsetAsBigInteger().equals(pkt_next);
	}

	@Override
	public PackedBytes getPcodePacked(Program program, InstructionContext context, UniqueAddressFactory uniqueFactory)
			throws UnknownInstructionException {
		HexagonPcodeEmitPacked emit = new HexagonPcodeEmitPacked(program);
		return emit.getPcodePacked(context, uniqueFactory);
	}

}
