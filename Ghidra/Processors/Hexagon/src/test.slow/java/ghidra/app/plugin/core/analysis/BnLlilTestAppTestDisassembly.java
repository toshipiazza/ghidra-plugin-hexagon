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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.analysis.HexagonAnalysisState.DuplexEncoding;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.UniqueAddressFactory;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class BnLlilTestAppTestDisassembly extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;

	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
	}

	@After
	public void tearDown() {
		if (program != null)
			env.release(program);
		program = null;
		env.dispose();
	}

	protected void setAnalysisOptions(String optionName) {
		int txId = program.startTransaction("Analyze");
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analysisOptions.setBoolean(optionName, false);
		program.endTransaction(txId, true);
	}
	
	void printAllPcodeAllPackets() throws UnknownInstructionException {
		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		
		for (HexagonPacket packet : state.getPackets()) {
			System.out.println("Instructions for packet @ " + packet.getMinAddress());
			for (Instruction insn : packet.getInstructions()) {
				System.out.println();
				System.out.println("  " + insn.toString());
				System.out.println();
				for (PcodeOp op : insn.getPcode()) {
					System.out.println("    " + op.toString());
				}
			}
			System.out.println();
			System.out.println("Pcode for whole packet");
			System.out.println();
			Instruction insn1 = packet.getInstructions().get(0);
			UniqueAddressFactory uniqueFactory = new UniqueAddressFactory(program.getAddressFactory(),
					program.getLanguage());
			List<PcodeOp> pcode = state.getPcode(insn1.getInstructionContext(), uniqueFactory);
			for (PcodeOp p : pcode) {
				System.out.println("  " + p);
			}
			System.out.println();
		}
	}

	@Test
	public void test_dualjump_cmp_jump_with_direct_jump() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);

		programBuilder.setBytes("1000", "06 62 03 10 08 40 00 58 01 c1 01 f3 c0 3f 10 48 c0 3f 20 48");

		programBuilder.disassemble("1000", 20, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		printAllPcodeAllPackets();
	}

	@Test
	public void test_hwloop() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);

		programBuilder.setBytes("1000", "52 40 00 69 01 c0 00 78 21 80 01 b0 00 c0 00 7f 00 c0 9f 52");

		programBuilder.disassemble("1000", 20, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		printAllPcodeAllPackets();
	}
}
