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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.DummyCancellableTaskMonitor;

public class HexagonPacketTestCodeBlock extends AbstractGhidraHeadedIntegrationTest {

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

	@Test
	public void testSimpleBlockModelSinglePacketNoControlFlow() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000", "01 c0 9d a0 00 e0 00 78 1e c0 1e 96");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new SimpleBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.TERMINATOR);
	}

	@Test
	public void testBasicBlockModelSinglePacketNoControlFlow() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000", "01 c0 9d a0 00 e0 00 78 1e c0 1e 96");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new BasicBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.TERMINATOR);
	}

	@Test
	public void testSimpleBlockModelSinglePacketWithControlFlow() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000", "08 62 03 10 0a 62 03 12 01 c1 01 f3");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new SimpleBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.FLOW);
	}

	@Test
	public void testBasicBlockModelSinglePacketWithControlFlow() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 12);

		programBuilder.setBytes("1000", "08 62 03 10 0a 62 03 12 01 c1 01 f3");

		programBuilder.disassemble("1000", 12, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new BasicBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.FLOW);
	}

	@Test
	public void testSimpleBlockModelSinglePacketWithControlFlowWithLabel() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 4);

		programBuilder.setBytes("1000", "c0 3f 10 48");

		programBuilder.disassemble("1000", 4, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		// Label created by HexagonPacketAnalyzer because of manual fallthrough override
		// Want to ensure that the block is not terminated in the middle by a label
		// TODO: can we remove the label/symbol created by the fallthrough override in
		// HexagonPacketAnalyzer instead?
		Symbol[] s = program.getSymbolTable().getSymbols(programBuilder.addr("1002"));
		assertEquals(s.length, 1);

		CodeBlockModel blockModel = new SimpleBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("1003"));
		assertEquals(block.getFlowType(), RefType.TERMINATOR);
	}

	@Test
	public void testBasicBlockModelSinglePacketWithControlFlowWithLabel() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 4);

		programBuilder.setBytes("1000", "c0 3f 10 48");

		programBuilder.disassemble("1000", 4, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		// Label created by HexagonPacketAnalyzer because of manual fallthrough override
		// Want to ensure that the block is not terminated in the middle by a label
		// TODO: can we remove the label/symbol created by the fallthrough override in
		// HexagonPacketAnalyzer instead?
		Symbol[] s = program.getSymbolTable().getSymbols(programBuilder.addr("1002"));
		assertEquals(s.length, 1);

		CodeBlockModel blockModel = new BasicBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("1003"));
		assertEquals(block.getFlowType(), RefType.TERMINATOR);
	}

	@Test
	public void testSimpleBlockModelGetMultipleDestinations() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 24);

		programBuilder.setBytes("1000", "08 62 03 10 0a 62 03 12 01 c1 01 f3 c0 3f 00 48 c0 3f 10 48 c0 3f 20 48");

		programBuilder.disassemble("1000", 24, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new SimpleBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.FLOW);

		AddressSet expected = new AddressSet();
		expected.add(programBuilder.addr("100c"));
		expected.add(programBuilder.addr("1010"));
		expected.add(programBuilder.addr("1014"));
		CodeBlockReferenceIterator iter = block.getDestinations(new DummyCancellableTaskMonitor());
		while (iter.hasNext()) {
			CodeBlockReference ref = iter.next();
			Address addr = ref.getDestinationAddress();
			assert expected.contains(addr);
			expected.delete(addr, addr);
		}
		assertEquals(0, expected.getNumAddresses());
	}

	@Test
	public void testBasicBlockModelGetMultipleDestinations() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", "hexagon:LE:32:default");
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");
		programBuilder.createMemory(".text", "1000", 24);

		programBuilder.setBytes("1000", "08 62 03 10 0a 62 03 12 01 c1 01 f3 c0 3f 00 48 c0 3f 10 48 c0 3f 20 48");

		programBuilder.disassemble("1000", 24, true);
		programBuilder.analyze();

		program.endTransaction(txId, true);

		CodeBlockModel blockModel = new BasicBlockModel(program);
		CodeBlock[] blocks = blockModel.getCodeBlocksContaining(programBuilder.addr("1000"), null);
		assertEquals(blocks.length, 1);
		CodeBlock block = blocks[0];
		assertEquals(block.getMinAddress(), programBuilder.addr("1000"));
		assertEquals(block.getMaxAddress(), programBuilder.addr("100b"));
		assertEquals(block.getFlowType(), RefType.FLOW);

		AddressSet expected = new AddressSet();
		expected.add(programBuilder.addr("100c"));
		expected.add(programBuilder.addr("1010"));
		expected.add(programBuilder.addr("1014"));
		CodeBlockReferenceIterator iter = block.getDestinations(new DummyCancellableTaskMonitor());
		while (iter.hasNext()) {
			CodeBlockReference ref = iter.next();
			Address addr = ref.getDestinationAddress();
			assert expected.contains(addr);
			expected.delete(addr, addr);
		}
		assertEquals(0, expected.getNumAddresses());
	}
}
