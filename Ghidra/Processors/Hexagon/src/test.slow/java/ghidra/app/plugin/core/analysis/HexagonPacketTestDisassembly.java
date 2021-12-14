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
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class HexagonPacketTestDisassembly extends AbstractGhidraHeadedIntegrationTest {

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

	/*
	 * Test several packets that are each only a single instruction with no control
	 * flow
	 */
	@Test
	public void testSingleInstructionPackets() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		programBuilder.setBytes("1000", "01 c0 9d a0 00 e0 00 78 1e c0 1e 96");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		assertEquals(3, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		state.debugPrintAllKnownPackets();
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(3, packets.size());

		HexagonPacket packet1 = packets.get(0);
		HexagonPacket packet2 = packets.get(1);
		HexagonPacket packet3 = packets.get(2);

		// all packets are terminated
		assertTrue(packet1.isTerminated());
		assertTrue(packet2.isTerminated());
		assertTrue(packet3.isTerminated());

		// all packets have only one instruction
		assertEquals(packet1.getMinAddress(), packet1.getMaxAddress());
		assertEquals(packet2.getMinAddress(), packet2.getMaxAddress());
		assertEquals(packet3.getMinAddress(), packet3.getMaxAddress());

		// all packets are in the right order
		assertEquals(packet1.getMinAddress().getOffset(), 0x1000);
		assertEquals(packet2.getMinAddress().getOffset(), 0x1004);
		assertEquals(packet3.getMinAddress().getOffset(), 0x1008);
	}

	/*
	 * Test one packet with several instructions, but there is no control flow
	 * within the packet except for the last instruction
	 */
	@Test
	public void testMultipleInstructionPackets() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		programBuilder.setBytes("1000", "01 41 01 f3 00 c0 80 52");

		programBuilder.disassemble("1000", 8, true);
		programBuilder.analyze();

		assertEquals(2, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		state.debugPrintAllKnownPackets();
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		HexagonPacket packet1 = packets.get(0);

		// packet is terminated
		assertTrue(packet1.isTerminated());

		// packet has two instructions
		assertEquals(packet1.getMinAddress().getOffset(), 0x1000);
		assertEquals(packet1.getMaxAddress().getOffset(), 0x1004);
	}

	/*
	 * Test one packet with several instructions, but there is control flow before
	 * the end of the packet
	 */
	@Test
	public void testControlFlowInMiddleOfPacket() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		programBuilder.setBytes("1000", "00 40 80 52 01 c1 01 f3");

		programBuilder.disassemble("1000", 8, true);
		programBuilder.analyze();

		assertEquals(2, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		state.debugPrintAllKnownPackets();
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		HexagonPacket packet1 = packets.get(0);

		// packet is terminated
		assertTrue(packet1.isTerminated());

		// packet has two instructions
		assertEquals(packet1.getMinAddress().getOffset(), 0x1000);
		assertEquals(packet1.getMaxAddress().getOffset(), 0x1004);
	}
}
