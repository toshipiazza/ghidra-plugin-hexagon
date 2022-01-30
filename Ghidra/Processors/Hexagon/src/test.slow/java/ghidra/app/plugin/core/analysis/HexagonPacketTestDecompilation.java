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

import java.util.Iterator;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class HexagonPacketTestDecompilation extends AbstractGhidraHeadedIntegrationTest {

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
	
	// Most of these tests are taken verbatim from https://github.com/google/binja-hexagon/tree/main/test_binaries

	@Test
	public void testAllocframe() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000",
				"01 c0 9d a0 00 e0 00 78 1e c0 1e 96");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "undefined4 FUN_00001000(void)\n"
				+ "\n"
				+ "{\n"
				+ "  return 0x100;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testMemoryStore() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000",
				"d1 48 01 00 16 c0 41 3c 00 c0 9f 52");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(undefined4 param_1,undefined4 *param_2)\n"
				+ "\n"
				+ "{\n"
				+ "  *param_2 = 0x123456;\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testStoreDotnew() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000",
				"03 42 01 f3 00 d2 a5 a1 00 c0 9f 52");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(undefined4 param_1,int param_2,int param_3,undefined4 param_4,undefined4 param_5,\n"
				+ "                 int *param_6)\n"
				+ "\n"
				+ "{\n"
				+ "  *param_6 = param_2 + param_3;\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testHwLoop() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 20);

		programBuilder.setBytes("1000",
				"52 40 00 69 01 c0 00 78 21 80 01 b0 00 c0 00 7f 00 c0 9f 52");

		programBuilder.disassemble("1000", 20, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(void)\n"
				+ "\n"
				+ "{\n"
				+ "  byte bVar1;\n"
				+ "  int iVar2;\n"
				+ "  \n"
				+ "  iVar2 = 10;\n"
				+ "  bVar1 = 0;\n"
				+ "  while( true ) {\n"
				+ "    if ((bool)(bVar1 & 3)) {\n"
				+ "      bVar1 = (bVar1 & 3) - 1;\n"
				+ "    }\n"
				+ "    if (iVar2 < 2) break;\n"
				+ "    iVar2 = iVar2 + -1;\n"
				+ "  }\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testHwLoop01() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 48);

		programBuilder.setBytes("1000",
				"00 c0 40 f2 28 c0 23 69 40 41 06 69 00 40 00 f2 00 40 00 78 08 e0 82 ab 23 c0 81 9b 00 83 00 f3 00 80 00 7f 00 c0 00 7f 08 c0 82 ab 00 c0 9f 52");

		programBuilder.disassemble("1000", 48, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);
		
		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "/* WARNING: Removing unreachable block (ram,0x00001008) */\n"
				+ "/* WARNING: Removing unreachable block (ram,0x0000101c) */\n"
				+ "\n"
				+ "void FUN_00001000(undefined4 param_1,int *param_2,int *param_3)\n"
				+ "\n"
				+ "{\n"
				+ "  bool bVar1;\n"
				+ "  byte bVar2;\n"
				+ "  int iVar3;\n"
				+ "  int iVar4;\n"
				+ "  int iVar5;\n"
				+ "  \n"
				+ "  iVar5 = 100;\n"
				+ "  iVar4 = 200;\n"
				+ "  bVar2 = 0;\n"
				+ "  iVar3 = 0;\n"
				+ "  while( true ) {\n"
				+ "    bVar1 = false;\n"
				+ "    iVar3 = iVar3 + *param_2;\n"
				+ "    if ((bool)(bVar2 & 3)) {\n"
				+ "      bVar2 = (bVar2 & 3) - 1;\n"
				+ "    }\n"
				+ "    if (iVar4 < 2) {\n"
				+ "      if (1 < iVar5) {\n"
				+ "        bVar1 = true;\n"
				+ "        iVar5 = iVar5 + -1;\n"
				+ "      }\n"
				+ "    }\n"
				+ "    else {\n"
				+ "      bVar1 = true;\n"
				+ "      iVar4 = iVar4 + -1;\n"
				+ "    }\n"
				+ "    if (!bVar1) break;\n"
				+ "    param_2 = param_2 + 1;\n"
				+ "    switch(0x1018) {\n" // FIXME: I think this is a problem with the decompiler, not with the pcode
				+ "    }\n"
				+ "  }\n"
				+ "  *param_3 = iVar3;\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	
	@Test
	public void testDualjumpDirectCallReorder() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 16);

		programBuilder.setBytes("1000",
				"08 40 00 5a 00 c3 82 a1 00 40 00 7f 00 c0 9f 52");

		programBuilder.disassemble("1000", 16, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 param_4)\n"
				+ "\n"
				+ "{\n"
				+ "  *param_3 = param_4;\n"
				+ "  func_0x00001010();\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testDualjumpTwoCmpJumps() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 24);

		programBuilder.setBytes("1000",
				"08 50 00 5c 0a 51 20 5c 01 c1 01 f3 c0 3f 00 48 c0 3f 10 48 c0 3f 21 48");

		programBuilder.disassemble("1000", 24, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "undefined4 FUN_00001000(undefined4 param_1)\n"
				+ "\n"
				+ "{\n"
				+ "  bool in_P0;\n"
				+ "  bool in_P1;\n"
				+ "  \n"
				+ "  if (in_P0) {\n"
				+ "    return 1;\n"
				+ "  }\n"
				+ "  if (in_P1) {\n"
				+ "    return 0;\n"
				+ "  }\n"
				+ "  return param_1;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}


	@Test
	public void testAddInt() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 32);

		programBuilder.setBytes("1000",
				"10 48 00 00 02 40 49 6a 00 c0 01 f3 00 40 00 7f 00 40 9f 52 00 40 00 7f 00 c0 82 a1 00 c0 00 7f");

		programBuilder.disassemble("1000", 32, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(int param_1,int param_2)\n"
				+ "\n"
				+ "{\n"
				+ "  iRam00021400 = param_2 + param_1;\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testCmpSignedInt() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 48);

		programBuilder.setBytes("1000",
				"0f 48 00 00 02 50 49 6a 00 c0 41 f2 1d 42 00 00 a1 44 00 7e 48 40 00 00 81 c6 80 7e 00 40 00 7f 00 40 9f 52 00 40 00 7f 00 c1 82 a1 00 c0 00 7f");

		programBuilder.disassemble("1000", 48, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(int param_1,int param_2)\n"
				+ "\n"
				+ "{\n"
				+ "  if (param_1 < param_2) {\n"
				+ "    uRam000213e0 = 0x8765;\n"
				+ "  }\n"
				+ "  else {\n"
				+ "    uRam000213e0 = 0x1234;\n"
				+ "  }\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testCmpUnsignedInt() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 48);

		programBuilder.setBytes("1000",
				"0e 48 00 00 02 58 49 6a 00 c0 61 f2 1d 42 00 00 a1 44 00 7e 48 40 00 00 81 c6 80 7e 00 40 00 7f 00 40 9f 52 00 40 00 7f 00 c1 82 a1 00 c0 00 7f");

		programBuilder.disassemble("1000", 48, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(uint param_1,uint param_2)\n"
				+ "\n"
				+ "{\n"
				+ "  if (param_1 < param_2) {\n"
				+ "    uRam000213b0 = 0x8765;\n"
				+ "  }\n"
				+ "  else {\n"
				+ "    uRam000213b0 = 0x1234;\n"
				+ "  }\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testInsert() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000", "e4 c0 00 78 00 c3 04 8f 00 c0 9f 52");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");
		
		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);

		assertEquals(getC, "\n"
				+ "uint FUN_00001000(uint param_1)\n"
				+ "\n"
				+ "{\n"
				+ "  return param_1 & 0xfffffff8 | 7;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testFactorial() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 80);

		programBuilder.setBytes("1000",
				"01 c0 9d a0 00 c0 9d a1 00 c0 9d 91 00 c0 00 75 00 c0 c0 6b 08 c0 00 5c 02 c0 00 58 81 c0 5d 3c 10 c0 00 58 00 c0 9d 91 e0 ff e0 bf ea ff ff 5b 01 c0 9d 91 00 c1 00 ed 01 c0 9d a1 02 c0 00 58 20 c0 9d 91 00 40 00 7f 00 40 00 7f 1e c0 1e 96");

		programBuilder.disassemble("1000", 80, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "int FUN_00001000(int param_1)\n"
				+ "\n"
				+ "{\n"
				+ "  int iStack12;\n"
				+ "  \n"
				+ "  if ((bool)~(param_1 == 0)) {\n"
				+ "    iStack12 = FUN_00001000(param_1 + -1);\n"
				+ "    iStack12 = iStack12 * param_1;\n"
				+ "  }\n"
				+ "  else {\n"
				+ "    iStack12 = 1;\n"
				+ "  }\n"
				+ "  return iStack12;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testCollatz() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 96);

		programBuilder.setBytes("1000",
				"01 c0 9d a0 01 c0 9d a1 02 c0 00 58 20 c0 9d 91 20 c0 00 75 1e c0 00 5c 02 c0 00 58 20 c0 9d 91 00 c0 00 85 0c c0 00 5c 02 c0 00 58 20 c0 9d 91 00 c1 00 8c 01 c0 9d a1 0a c0 00 58 20 c0 9d 91 23 c0 00 d8 01 c0 9d a1 02 c0 00 58 e0 ff ff 59 00 40 00 7f 00 40 00 7f 00 40 00 7f 1e c0 1e 96");

		programBuilder.disassemble("1000", 96, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "void FUN_00001000(uint param_1)\n"
				+ "\n"
				+ "{\n"
				+ "  uint uStack12;\n"
				+ "  \n"
				+ "  uStack12 = param_1;\n"
				+ "  while (uStack12 != 1) {\n"
				+ "    if ((uStack12 & 1) == 0) {\n"
				+ "      uStack12 = uStack12 >> 1;\n"
				+ "    }\n"
				+ "    else {\n"
				+ "      uStack12 = uStack12 * 3 + 1;\n"
				+ "    }\n"
				+ "  }\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testCallReturnFlowOverride() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 68);

		programBuilder.setBytes("1000",
				"00 c0 9d a0 02 c0 00 58 00 40 00 58 00 c0 00 7f 02 c0 9d a0 ff e0 9e a7 fe e1 9e a7 e0 ff 9e 97 c1 ff 9e 97 01 c1 00 f3 08 48 00 00 00 d4 49 6a fd e0 9e a7 00 c1 80 a1 e0 ff 9e 97 fc e0 9e a7 e0 ff ff 5b");

		programBuilder.disassemble("1000", 68, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		txId = program.startTransaction("Add functions and FlowOverride");

		programBuilder.createFunction("1000");
		programBuilder.createFunction("1010");
		program.getListing().getInstructionAt(programBuilder.addr("1040")).setFlowOverride(FlowOverride.CALL_RETURN);

		program.endTransaction(txId, true);

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1010")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */\n"
				+ "\n"
				+ "void FUN_00001010(int param_1,int param_2)\n"
				+ "\n"
				+ "{\n"
				+ "  _DAT_00021250 = param_1 + param_2;\n"
				+ "  FUN_00001000();\n"
				+ "  return;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testReorderedDotNewPredicates() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 16);

		programBuilder.setBytes("1000", "20 65 80 7e 06 c0 0a 10 c0 3f 00 48 c0 3f 10 48");

		programBuilder.disassemble("1000", 16, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "undefined4 FUN_00001000(void)\n"
				+ "\n"
				+ "{\n"
				+ "  int unaff_R18;\n"
				+ "  \n"
				+ "  if (unaff_R18 == 0) {\n"
				+ "    return 1;\n"
				+ "  }\n"
				+ "  return 0;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

	@Test
	public void testAutoAndPredicates() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 16);

		// see https://github.com/qemu/qemu/blob/d940d468e29bff5eb5669c0dd8f3de0c3de17bfb/tests/tcg/hexagon/misc.c#L203 (cmpnd_cmp_jump test case)
		programBuilder.setBytes("1000", "06 47 05 10 e0 c0 06 75 c0 3f c0 48 c0 3f d0 48");

		programBuilder.disassemble("1000", 16, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		programBuilder.createFunction("1000");

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(program);

		DecompileResults results = ifc
				.decompileFunction(program.getListing().getFunctionAt(programBuilder.addr("1000")), 0, null);

		System.out.println("Optimized pcode:");
		Iterator<PcodeOpAST> pcodeOpIter = results.getHighFunction().getPcodeOps();
		while (pcodeOpIter.hasNext()) {
			System.out.println(pcodeOpIter.next());
		}

		String getC = results.getDecompiledFunction().getC();
		System.out.println(getC);
		assertEquals(getC, "\n"
				+ "undefined4 FUN_00001000(void)\n"
				+ "\n"
				+ "{\n"
				+ "  int in_R5;\n"
				+ "  int in_R6;\n"
				+ "  \n"
				+ "  if (in_R5 != 7 || in_R6 != 7) {\n"
				+ "    return 0xc;\n"
				+ "  }\n"
				+ "  return 0xd;\n"
				+ "}\n"
				+ "\n"
				+ "");
	}

}
