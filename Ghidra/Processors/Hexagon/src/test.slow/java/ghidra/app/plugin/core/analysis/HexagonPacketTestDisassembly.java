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

import java.math.BigInteger;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
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
	
	void debugPrintAllKnownPackets(HexagonAnalysisState state) {
		for (HexagonPacket packet : state.getPackets()) {
			System.out.println(packet);
		}
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
		
		program.endTransaction(txId, true);

		assertEquals(3, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(3, packets.size());

		HexagonPacket pkt1 = packets.get(0);
		HexagonPacket pkt2 = packets.get(1);
		HexagonPacket pkt3 = packets.get(2);

		// all packets are terminated
		assertTrue(pkt1.isTerminated());
		assertTrue(pkt2.isTerminated());
		assertTrue(pkt3.isTerminated());

		// all packets have only one instruction
		assertEquals(pkt1.getMinAddress(), pkt1.getMaxAddress());
		assertEquals(pkt2.getMinAddress(), pkt2.getMaxAddress());
		assertEquals(pkt3.getMinAddress(), pkt3.getMaxAddress());

		// all packets are in the right order
		assertEquals(pkt1.getMinAddress().getOffset(), 0x1000);
		assertEquals(pkt2.getMinAddress().getOffset(), 0x1004);
		assertEquals(pkt3.getMinAddress().getOffset(), 0x1008);

		// pkt_start and pkt_next are correct
		Register pktSReg = program.getProgramContext().getRegister("pkt_start");
		Register pktNReg = program.getProgramContext().getRegister("pkt_next");
		assertEquals(program.getProgramContext().getValue(pktSReg, pkt1.getMinAddress(), false).intValue(), 0x1000);
		assertEquals(program.getProgramContext().getValue(pktNReg, pkt1.getMinAddress(), false).intValue(), 0x1004);
		assertEquals(program.getProgramContext().getValue(pktSReg, pkt2.getMinAddress(), false).intValue(), 0x1004);
		assertEquals(program.getProgramContext().getValue(pktNReg, pkt2.getMinAddress(), false).intValue(), 0x1008);
		assertEquals(program.getProgramContext().getValue(pktSReg, pkt3.getMinAddress(), false).intValue(), 0x1008);
		assertEquals(program.getProgramContext().getValue(pktNReg, pkt3.getMinAddress(), false).intValue(), 0x100c);
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

		program.endTransaction(txId, true);

		assertEquals(2, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		HexagonPacket packet1 = packets.get(0);

		// packet is terminated
		assertTrue(packet1.isTerminated());

		// packet has two instructions
		assertEquals(packet1.getMinAddress().getOffset(), 0x1000);
		assertEquals(packet1.getMaxAddress().getOffset(), 0x1004);
		
		// verify fallthrough of first instruction in packet
		Instruction insn1 = program.getListing().getInstructionAt(packet1.getMinAddress());
		assertTrue(insn1.hasFallthrough());
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

		program.endTransaction(txId, true);

		assertEquals(2, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		HexagonPacket packet1 = packets.get(0);

		// packet is terminated
		assertTrue(packet1.isTerminated());

		// packet has two instructions
		assertEquals(packet1.getMinAddress().getOffset(), 0x1000);
		assertEquals(packet1.getMaxAddress().getOffset(), 0x1004);

		// verify fallthrough of first instruction in packet
		Instruction insn1 = program.getListing().getInstructionAt(packet1.getMinAddress());
		assertTrue(insn1.hasFallthrough());
	}
}
