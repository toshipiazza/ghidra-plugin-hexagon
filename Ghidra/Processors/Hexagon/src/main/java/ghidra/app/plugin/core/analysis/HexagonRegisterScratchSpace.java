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
