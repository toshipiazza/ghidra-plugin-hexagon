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
package ghidra.app.util.bin.format.elf;

public class Hexagon_ElfRelocationConstants {

    // "Qualcomm Hexagon Application Binary Interface User Guide" table 12-5
    public static final int R_HEX_NONE = 0;
    public static final int R_HEX_B22_PCREL = 1;
    public static final int R_HEX_B15_PCREL = 2;
    public static final int R_HEX_B7_PCREL = 3;
    public static final int R_HEX_LO16 = 4;
    public static final int R_HEX_HI16 = 5;
    public static final int R_HEX_32 = 6;
    public static final int R_HEX_16 = 7;
    public static final int R_HEX_8 = 8;
    public static final int R_HEX_GPREL16_0 = 9;
    public static final int R_HEX_GPREL16_1 = 10;
    public static final int R_HEX_GPREL16_2 = 11;
    public static final int R_HEX_GPREL16_3 = 12;
    public static final int R_HEX_HL16 = 13;
    public static final int R_HEX_B13_PCREL = 14;
    public static final int R_HEX_B9_PCREL = 15;
    public static final int R_HEX_B32_PCREL_X = 16;
    public static final int R_HEX_32_6_X = 17;
    public static final int R_HEX_B22_PCREL_X = 18;
    public static final int R_HEX_B15_PCREL_X = 19;
    public static final int R_HEX_B13_PCREL_X = 20;
    public static final int R_HEX_B9_PCREL_X = 21;
    public static final int R_HEX_B7_PCREL_X = 22;
    public static final int R_HEX_16_X = 23;
    public static final int R_HEX_12_X = 24;
    public static final int R_HEX_11_X = 25;
    public static final int R_HEX_10_X = 26;
    public static final int R_HEX_9_X = 27;
    public static final int R_HEX_8_X = 28;
    public static final int R_HEX_7_X = 29;
    public static final int R_HEX_6_X = 30;
    public static final int R_HEX_32_PCREL = 31;
    public static final int R_HEX_COPY = 32;
    public static final int R_HEX_GLOB_DAT = 33;
    public static final int R_HEX_JMP_SLOT = 34;
    public static final int R_HEX_RELATIVE = 35;
    public static final int R_HEX_PLT_B22_PCREL = 36;
    public static final int R_HEX_GOTREL_LO16 = 37;
    public static final int R_HEX_GOTREL_HI16 = 38;
    public static final int R_HEX_GOTREL_32 = 39;
    public static final int R_HEX_GOT_LO16 = 40;
    public static final int R_HEX_GOT_HI16 = 41;
    public static final int R_HEX_GOT_32 = 42;
    public static final int R_HEX_GOT_16 = 43;
    public static final int R_HEX_DTPMOD_32 = 44;
    public static final int R_HEX_DTPREL_LO16 = 45;
    public static final int R_HEX_DTPREL_HI16 = 46;
    public static final int R_HEX_DTPREL_32 = 47;
    public static final int R_HEX_DTPREL_16 = 48;
    public static final int R_HEX_GD_PLT_B22_PCREL = 49;
    public static final int R_HEX_GD_GOT_LO16 = 50;
    public static final int R_HEX_GD_GOT_HI16 = 51;
    public static final int R_HEX_GD_GOT_32 = 52;
    public static final int R_HEX_GD_GOT_16 = 53;
    public static final int R_HEX_IE_LO16 = 54;
    public static final int R_HEX_IE_HI16 = 55;
    public static final int R_HEX_IE_32 = 56;
    public static final int R_HEX_IE_GOT_LO16 = 57;
    public static final int R_HEX_IE_GOT_HI16 = 58;
    public static final int R_HEX_IE_GOT_32 = 59;
    public static final int R_HEX_IE_GOT_16 = 60;
    public static final int R_HEX_TPREL_LO16 = 61;
    public static final int R_HEX_TPREL_HI16 = 62;
    public static final int R_HEX_TPREL_32 = 63;
    public static final int R_HEX_TPREL_16 = 64;
    public static final int R_HEX_6_PCREL_X = 65;
    public static final int R_HEX_GOTREL_32_6_X = 66;
    public static final int R_HEX_GOTREL_16_X = 67;
    public static final int R_HEX_GOTREL_11_X = 68;
    public static final int R_HEX_GOT_32_6_X = 69;
    public static final int R_HEX_GOT_16_X = 70;
    public static final int R_HEX_GOT_11_X = 71;
    public static final int R_HEX_DTPREL_32_6_X = 72;
    public static final int R_HEX_DTPREL_16_X = 73;
    public static final int R_HEX_DTPREL_11_X = 74;
    public static final int R_HEX_GD_GOT_32_6_X = 75;
    public static final int R_HEX_GD_GOT_16_X = 76;
    public static final int R_HEX_GD_GOT_11_X = 77;
    public static final int R_HEX_IE_32_6_X = 78;
    public static final int R_HEX_IE_16_X = 79;
    public static final int R_HEX_IE_GOT_32_6_X = 80;
    public static final int R_HEX_IE_GOT_16_X = 81;
    public static final int R_HEX_IE_GOT_11_X = 82;
    public static final int R_HEX_TPREL_32_6_X = 83;
    public static final int R_HEX_TPREL_16_X = 84;
    public static final int R_HEX_TPREL_11_X = 85;
    public static final int R_HEX_LD_PLT_B22_PCREL = 86;
    public static final int R_HEX_LD_GOT_LO16 = 87;
    public static final int R_HEX_LD_GOT_HI16 = 88;
    public static final int R_HEX_LD_GOT_32 = 89;
    public static final int R_HEX_LD_GOT_16 = 90;
    public static final int R_HEX_LD_GOT_32_6_X = 91;
    public static final int R_HEX_LD_GOT_16_X = 92;
    public static final int R_HEX_LD_GOT_11_X = 93;
    public static final int R_HEX_23_REG = 94;
    public static final int R_HEX_GD_PLT_B22_PCREL_X = 95;
    public static final int R_HEX_GD_PLT_B32_PCREL_X = 96;
    public static final int R_HEX_LD_PLT_B22_PCREL_X = 97;
    public static final int R_HEX_LD_PLT_B32_PCREL_X = 98;
    public static final int R_HEX_27_REG = 99;

}
