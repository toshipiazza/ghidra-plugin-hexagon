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
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;

class HexagonExternalBranch {

	Address insnAddress;
	FlowOverride override;
	int opcode;
	Varnode destVn;
	Varnode condVn;
	boolean hasConditional;
	int branchNoInInsn;

	HexagonExternalBranch(HexagonPcodeEmitPacked emit, Instruction instr, int opcode, Varnode destVn,
			boolean hasConditional, int branchNoInInsn, boolean handleFlowOverride) {
		insnAddress = instr.getAddress();
		if (handleFlowOverride) {
			this.override = instr.getFlowOverride();
		} else {
			// ignore flow overrides
			this.override = FlowOverride.NONE;
		}
		this.opcode = opcode;
		condVn = new Varnode(emit.uniqueFactory.getNextUniqueAddress(), 1);
		if (destVn.isRegister()) {
			Register reg = emit.program.getRegister(destVn);
			assert !emit.regWrittenInInstruction(instr, reg);
			this.destVn = emit.regTempSpace.getScratchVn(destVn);
		} else {
			this.destVn = destVn;
		}
		this.hasConditional = hasConditional;
		this.branchNoInInsn = branchNoInInsn;
		if (branchNoInInsn > 0) {
			this.override = FlowOverride.NONE;
		}
	}
}
