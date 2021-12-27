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

	void verifyAllPrefixes(HexagonAnalysisState state) throws UnknownInstructionException {
		for (HexagonPacket packet : state.getPackets()) {
			List<Instruction> insns = packet.getInstructions();
			assertEquals(state.getMnemonicPrefix(insns.get(0)), "");
			for (int i = 1; i < insns.size(); i++) {
				assertEquals(state.getMnemonicPrefix(insns.get(i)), "||");
			}
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

		verifyAllPrefixes(state);
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

		verifyAllPrefixes(state);
	}

	@Test
	public void testDuplexInstruction() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		programBuilder.setBytes("1000", "c0 3f 10 48");

		programBuilder.disassemble("1000", 4, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		assertEquals(2, program.getListing().getNumInstructions());

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		HexagonPacket packet1 = packets.get(0);

		assertEquals(state.duplexInsns.get(packet1.getMaxAddress().add(0)), DuplexEncoding.L2);
		assertEquals(state.duplexInsns.get(packet1.getMaxAddress().add(2)), DuplexEncoding.A);

		verifyAllPrefixes(state);
	}

	@Test
	public void testImmext() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		programBuilder.setBytes("1000", "d1 48 01 00 16 c0 41 3c");

		programBuilder.disassemble("1000", 8, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		assertEquals(2, program.getListing().getNumInstructions());
		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		assertEquals(1, packets.size());

		// immext must have propagated if imm is correct
		Instruction inst2 = program.getListing().getInstructionAt(packets.get(0).getMaxAddress());
		assertEquals("0x123456", inst2.getDefaultOperandRepresentation(2));

		verifyAllPrefixes(state);
	}

	@Test
	public void testDotNewPredicates() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		// test_dualjump_two_cmp_jumps
		programBuilder.setBytes("1000", "08 62 03 10 0a 62 03 12 01 c1 01 f3 c0 3f 00 48 c0 3f 10 48 c0 3f 20 48");

		programBuilder.disassemble("1000", 24, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		assertEquals(9, program.getListing().getNumInstructions());
		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);
		List<HexagonPacket> packets = state.getPackets();

		verifyAllPrefixes(state);

		HexagonPacket packet1 = packets.get(0);
		Instruction insn1 = packet1.getInstructions().get(0);
		UniqueAddressFactory uniqueFactory = new UniqueAddressFactory(program.getAddressFactory(),
				program.getLanguage());
		List<PcodeOp> pcode = state.getPcode(insn1.getInstructionContext(), uniqueFactory);
		for (PcodeOp p : pcode) {
			System.out.println(p);
		}

		/*
		 * Pcode should resemble
		 * 
		 * tmp1 = 0 tmp2 = 0 tmp3 = R1 tmp4 = P0 tmp5 = P1 tmp6 = R3
		 * 
		 * J4_cmpeqi_tp0_jump_t R3 0x2 0x1010
		 * 
		 * u0x1100 = 0x1010 u0x1080 = 2 P0 = tmp6 == u0x1080 u0x26e00 = P0 CBRANCH 2 ,
		 * u0x26e00 BRANCH 3 tmp2 = 1 BRANCH 1
		 * 
		 * J4_cmpeqi_tp1_jump_t R3 0x2 0x1014
		 * 
		 * u0x1700 = 0x1014 u0x1680 = 2 P1 = tmp6 == u0x1680 u0x27800 = P1 CBRANCH 2 ,
		 * u0x27800 BRANCH 3 tmp1 = 1 BRANCH 1
		 * 
		 * A2_add R1 R1 R1
		 * 
		 * R1 = tmp3 + tmp3
		 * 
		 * CBRANCH 2 , tmp2 BRANCHIND u0x1100 CBRANCH 2 , tmp1 BRANCHIND u0x1700
		 * 
		 */
	}

	@Test
	public void testNewValueOperands() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);
		// test_dualjump_two_cmp_jumps
		programBuilder.setBytes("1000", "03 42 01 f3 00 d2 a5 a1 00 c0 9f 52");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);

		// S2_storerinew_io R5 0x2 0x0
		Address addr2 = state.getPackets().get(0).getMaxAddress();
		Instruction insn2 = program.getListing().getInstructionAt(addr2);
		PcodeOp[] ops = insn2.getPcode();

		assertNotEquals(ops[0].getOpcode(), PcodeOp.UNIMPLEMENTED);

		verifyAllPrefixes(state);
	}

	@Test
	public void testEndloop0() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 64);

		// { loop0(data_2028c,#0xa)  
		//   R1 = #0x0 }
		// { R1 = add(R1,#0x1)
		//   nop }  :endloop0
		// { jumpr LR }

		programBuilder.setBytes("1000", "52 40 00 69 01 c0 00 78 21 80 01 b0 00 c0 00 7f 00 c0 9f 52");

		programBuilder.disassemble("1000", 20, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		HexagonAnalysisState state = HexagonAnalysisState.getState(program);
		debugPrintAllKnownPackets(state);

		verifyAllPrefixes(state);
		
		// endloop was correctly detected
		assertEquals(state.getPackets().get(1).toString(), "{ A2_addi R1 R1 0x1 ; A2_nop }:endloop0 @ 00001008");
		
		// endloop contextreg was correctly set
		Register endloop = program.getProgramContext().getRegister("endloop");
		assertEquals(program.getProgramContext().getValue(endloop, state.getPackets().get(1).getMaxAddress(), false).intValue(), 1);

		for (HexagonPacket packet : state.getPackets()) {
			System.out.println("------- pcode for packet " + packet);
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
}
