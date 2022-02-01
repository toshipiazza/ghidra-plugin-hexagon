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
			boolean hasConditional, int branchNoInInsn) {
		insnAddress = instr.getAddress();
		this.override = instr.getFlowOverride();
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