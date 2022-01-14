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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.util.bin.format.elf.ElfConstants;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfRelocation;
import ghidra.app.util.bin.format.elf.ElfSymbol;
import ghidra.app.util.bin.format.elf.Hexagon_ElfRelocationConstants;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

public class Hexagon_ElfRelocationHandler extends ElfRelocationHandler {

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_HEXAGON;
	}

	@Override
	public void relocate(ElfRelocationContext elfRelocationContext, ElfRelocation relocation, Address relocationAddress)
			throws MemoryAccessException, NotFoundException {

		ElfHeader elf = elfRelocationContext.getElfHeader();
		if (elf.e_machine() != ElfConstants.EM_HEXAGON) {
			return;
		}

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		int type = relocation.getType();
		if (type == Hexagon_ElfRelocationConstants.R_HEX_NONE) {
			return;
		}

		int symbolIndex = relocation.getSymbolIndex();

		long addend = relocation.getAddend(); // will be 0 for REL case

		ElfSymbol sym = elfRelocationContext.getSymbol(symbolIndex);
		String symbolName = sym != null ? sym.getNameAsString() : null;

		long symbolValue = elfRelocationContext.getSymbolValue(sym);

		switch (type) {
		case Hexagon_ElfRelocationConstants.R_HEX_32:
			int newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
			memory.setInt(relocationAddress, newValue);
			break;
		case Hexagon_ElfRelocationConstants.R_HEX_COPY:
			markAsWarning(program, relocationAddress, "R_HEX_COPY", symbolName, symbolIndex,
					"Runtime copy not supported", elfRelocationContext.getLog());
			break;
		case Hexagon_ElfRelocationConstants.R_HEX_GLOB_DAT:
			newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
			memory.setInt(relocationAddress, newValue);
			break;
		case Hexagon_ElfRelocationConstants.R_HEX_JMP_SLOT:
			newValue = (((int) symbolValue + (int) addend) & 0xffffffff);
			memory.setInt(relocationAddress, newValue);
			break;
		case Hexagon_ElfRelocationConstants.R_HEX_RELATIVE:
			newValue = (((int) elfRelocationContext.getImageBaseWordAdjustmentOffset() + (int) addend) & 0xffffffff);
			memory.setInt(relocationAddress, newValue);
			break;
		default:
			markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName, elfRelocationContext.getLog());
			break;
		}
	}

}
