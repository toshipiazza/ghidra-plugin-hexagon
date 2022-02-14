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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.field.TextFieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.listing.Instruction;
import ghidra.program.util.ParallelInstructionLocation;
import ghidra.program.util.ProgramLocation;

import java.awt.*;
import java.math.BigInteger;

/**
  *  Generates Parallel execution marks '}' for those language which have a
  *  ParallelFieldLanguageHelper class and have specified the corresponding
  *  language property in the pspec.
  */
public class ParallelInstructionSuffixFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "Parallel Suffix";
	public static final Color DEFAULT_COLOR = new Color(0, 0, 128);

	/**
	 * Default constructor.
	 */
	public ParallelInstructionSuffixFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private ParallelInstructionSuffixFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
                                                  Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String name, Object oldValue,
			Object newValue) {
		// don't care
	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}

		Instruction instr = (Instruction) obj;
		ParallelInstructionLanguageHelper helper =
			instr.getProgram().getLanguage().getParallelInstructionHelper();
		if (helper == null) {
			return null;
		}

		String fieldText = helper.getMnemonicSuffix(instr);
		if (fieldText == null) {
			return null;
		}

		AttributedString as =
			new AttributedString(fieldText, color, getMetrics(), false, underlineColor);
		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	/**
	 * @see FieldFactory#getProgramLocation(int, int, ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) obj;

		return new ParallelInstructionLocation(instr.getProgram(), instr.getMinAddress(), col);
	}

	/**
	 * @see FieldFactory#getFieldLocation(ListingField, BigInteger, int, ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (programLoc instanceof ParallelInstructionLocation) {
			return new FieldLocation(index, fieldNum, 0,
				((ParallelInstructionLocation) programLoc).getCharOffset());
		}
		return null;
	}

	/**
	 * @see FieldFactory#acceptsType(int, Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return category == FieldFormatModel.INSTRUCTION_OR_DATA;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel model, HighlightProvider hsProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new ParallelInstructionSuffixFieldFactory(model, hsProvider, displayOptions, fieldOptions);
	}

	/**
	 * @see FieldFactory#getDefaultColor()
	 */
	@Override
	public Color getDefaultColor() {
		return Color.black;
	}
}
