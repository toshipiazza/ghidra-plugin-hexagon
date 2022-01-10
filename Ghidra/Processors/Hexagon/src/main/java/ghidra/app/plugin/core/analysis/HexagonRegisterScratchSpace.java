package ghidra.app.plugin.core.analysis;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;

class HexagonRegisterScratchSpace {

	Address[] scratch;

	HexagonRegisterScratchSpace(Program program, UniqueAddressFactory uniqueFactory) {
		// SGP1 is the last register in the address space; if this changes then
		// this line will have to change as well
		int numSlots = (int) (program.getRegister("SGP1").getAddress().add(4).getOffset() / 4);
		scratch = new Address[numSlots];

		for (int i = 0; i < numSlots; i += 2) {
			Address uniq = uniqueFactory.getNextUniqueAddress();
			scratch[i + 0] = uniq.add(0);
			scratch[i + 1] = uniq.add(4);
		}
	}

	Varnode getScratchReg(Register register) {
		long idx = register.getAddress().getOffset() / 4;
		long off = register.getAddress().getOffset() % 4;
		return new Varnode(scratch[(int) idx].add(off), register.getAddress().getSize());
	}

	Varnode getScratchVn(Varnode vn) {
		long idx = vn.getAddress().getOffset() / 4;
		long off = vn.getAddress().getOffset() % 4;
		return new Varnode(scratch[(int) idx].add(off), vn.getSize());
	}

}