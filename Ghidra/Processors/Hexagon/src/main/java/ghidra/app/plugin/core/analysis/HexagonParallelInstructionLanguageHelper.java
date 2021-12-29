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
        if (pkt_start == null) {
            // not yet analyzed
            return "";
        }
        if (pkt_start.equals(instr.getAddress().getOffsetAsBigInteger())) {
            // start of packet
            return "";
        }
        // middle of packet
        return "||";
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
