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

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.Msg;

class HexagonInstructionInfo {
	private static final Map<String, Integer> dot_new_producers;

	static {
		// dot-new producers are those instructions which write to a 32-bit GPR.
		// Since no dot-new operands appear in DUPLEX instructions (instructions
		// which must terminate the packet), dot-new produces cannot be DUPLEX
		// either
		dot_new_producers = new HashMap<>();
		dot_new_producers.put("J4_jumpseti", 0);
		dot_new_producers.put("J4_jumpsetr", 0);
		dot_new_producers.put("L2_loadrub_io", 0);
		dot_new_producers.put("L4_loadrub_ur", 0);
		dot_new_producers.put("L4_loadrub_ap", 0);
		dot_new_producers.put("L2_loadrub_pr", 0);
		dot_new_producers.put("L2_loadrub_pbr", 0);
		dot_new_producers.put("L2_loadrub_pi", 0);
		dot_new_producers.put("L2_loadrub_pci", 0);
		dot_new_producers.put("L2_loadrub_pcr", 0);
		dot_new_producers.put("L2_loadrb_io", 0);
		dot_new_producers.put("L4_loadrb_ur", 0);
		dot_new_producers.put("L4_loadrb_ap", 0);
		dot_new_producers.put("L2_loadrb_pr", 0);
		dot_new_producers.put("L2_loadrb_pbr", 0);
		dot_new_producers.put("L2_loadrb_pi", 0);
		dot_new_producers.put("L2_loadrb_pci", 0);
		dot_new_producers.put("L2_loadrb_pcr", 0);
		dot_new_producers.put("L2_loadruh_io", 0);
		dot_new_producers.put("L4_loadruh_ur", 0);
		dot_new_producers.put("L4_loadruh_ap", 0);
		dot_new_producers.put("L2_loadruh_pr", 0);
		dot_new_producers.put("L2_loadruh_pbr", 0);
		dot_new_producers.put("L2_loadruh_pi", 0);
		dot_new_producers.put("L2_loadruh_pci", 0);
		dot_new_producers.put("L2_loadruh_pcr", 0);
		dot_new_producers.put("L2_loadrh_io", 0);
		dot_new_producers.put("L4_loadrh_ur", 0);
		dot_new_producers.put("L4_loadrh_ap", 0);
		dot_new_producers.put("L2_loadrh_pr", 0);
		dot_new_producers.put("L2_loadrh_pbr", 0);
		dot_new_producers.put("L2_loadrh_pi", 0);
		dot_new_producers.put("L2_loadrh_pci", 0);
		dot_new_producers.put("L2_loadrh_pcr", 0);
		dot_new_producers.put("L2_loadri_io", 0);
		dot_new_producers.put("L4_loadri_ur", 0);
		dot_new_producers.put("L4_loadri_ap", 0);
		dot_new_producers.put("L2_loadri_pr", 0);
		dot_new_producers.put("L2_loadri_pbr", 0);
		dot_new_producers.put("L2_loadri_pi", 0);
		dot_new_producers.put("L2_loadri_pci", 0);
		dot_new_producers.put("L2_loadri_pcr", 0);
		dot_new_producers.put("L4_loadrd_ap", 1);
		dot_new_producers.put("L2_loadrd_pr", 1);
		dot_new_producers.put("L2_loadrd_pbr", 1);
		dot_new_producers.put("L2_loadrd_pi", 1);
		dot_new_producers.put("L2_loadrd_pci", 1);
		dot_new_producers.put("L2_loadrd_pcr", 1);
		dot_new_producers.put("L2_loadbzw2_io", 0);
		dot_new_producers.put("L4_loadbzw2_ur", 0);
		dot_new_producers.put("L4_loadbzw2_ap", 0);
		dot_new_producers.put("L2_loadbzw2_pr", 0);
		dot_new_producers.put("L2_loadbzw2_pbr", 0);
		dot_new_producers.put("L2_loadbzw2_pi", 0);
		dot_new_producers.put("L2_loadbzw2_pci", 0);
		dot_new_producers.put("L2_loadbzw2_pcr", 0);
		dot_new_producers.put("L4_loadbzw4_ap", 1);
		dot_new_producers.put("L2_loadbzw4_pr", 1);
		dot_new_producers.put("L2_loadbzw4_pbr", 1);
		dot_new_producers.put("L2_loadbzw4_pi", 1);
		dot_new_producers.put("L2_loadbzw4_pci", 1);
		dot_new_producers.put("L2_loadbzw4_pcr", 1);
		dot_new_producers.put("L2_loadbsw2_io", 0);
		dot_new_producers.put("L4_loadbsw2_ur", 0);
		dot_new_producers.put("L4_loadbsw2_ap", 0);
		dot_new_producers.put("L2_loadbsw2_pr", 0);
		dot_new_producers.put("L2_loadbsw2_pbr", 0);
		dot_new_producers.put("L2_loadbsw2_pi", 0);
		dot_new_producers.put("L2_loadbsw2_pci", 0);
		dot_new_producers.put("L2_loadbsw2_pcr", 0);
		dot_new_producers.put("L4_loadbsw4_ap", 1);
		dot_new_producers.put("L2_loadbsw4_pr", 1);
		dot_new_producers.put("L2_loadbsw4_pbr", 1);
		dot_new_producers.put("L2_loadbsw4_pi", 1);
		dot_new_producers.put("L2_loadbsw4_pci", 1);
		dot_new_producers.put("L2_loadbsw4_pcr", 1);
		dot_new_producers.put("L4_loadalignh_ap", 1);
		dot_new_producers.put("L2_loadalignh_pr", 1);
		dot_new_producers.put("L2_loadalignh_pbr", 1);
		dot_new_producers.put("L2_loadalignh_pi", 1);
		dot_new_producers.put("L2_loadalignh_pci", 1);
		dot_new_producers.put("L2_loadalignh_pcr", 1);
		dot_new_producers.put("L4_loadalignb_ap", 1);
		dot_new_producers.put("L2_loadalignb_pr", 1);
		dot_new_producers.put("L2_loadalignb_pbr", 1);
		dot_new_producers.put("L2_loadalignb_pi", 1);
		dot_new_producers.put("L2_loadalignb_pci", 1);
		dot_new_producers.put("L2_loadalignb_pcr", 1);
		dot_new_producers.put("S2_storerb_pi", 0);
		dot_new_producers.put("S4_storerb_ap", 0);
		dot_new_producers.put("S2_storerb_pr", 0);
		dot_new_producers.put("S2_storerb_pbr", 0);
		dot_new_producers.put("S2_storerb_pci", 0);
		dot_new_producers.put("S2_storerb_pcr", 0);
		dot_new_producers.put("S2_storerh_pi", 0);
		dot_new_producers.put("S4_storerh_ap", 0);
		dot_new_producers.put("S2_storerh_pr", 0);
		dot_new_producers.put("S2_storerh_pbr", 0);
		dot_new_producers.put("S2_storerh_pci", 0);
		dot_new_producers.put("S2_storerh_pcr", 0);
		dot_new_producers.put("S2_storerf_pi", 0);
		dot_new_producers.put("S4_storerf_ap", 0);
		dot_new_producers.put("S2_storerf_pr", 0);
		dot_new_producers.put("S2_storerf_pbr", 0);
		dot_new_producers.put("S2_storerf_pci", 0);
		dot_new_producers.put("S2_storerf_pcr", 0);
		dot_new_producers.put("S2_storeri_pi", 0);
		dot_new_producers.put("S4_storeri_ap", 0);
		dot_new_producers.put("S2_storeri_pr", 0);
		dot_new_producers.put("S2_storeri_pbr", 0);
		dot_new_producers.put("S2_storeri_pci", 0);
		dot_new_producers.put("S2_storeri_pcr", 0);
		dot_new_producers.put("S2_storerd_pi", 0);
		dot_new_producers.put("S4_storerd_ap", 0);
		dot_new_producers.put("S2_storerd_pr", 0);
		dot_new_producers.put("S2_storerd_pbr", 0);
		dot_new_producers.put("S2_storerd_pci", 0);
		dot_new_producers.put("S2_storerd_pcr", 0);
		dot_new_producers.put("S2_storerinew_pi", 0);
		dot_new_producers.put("S4_storerinew_ap", 0);
		dot_new_producers.put("S2_storerinew_pr", 0);
		dot_new_producers.put("S2_storerinew_pbr", 0);
		dot_new_producers.put("S2_storerinew_pci", 0);
		dot_new_producers.put("S2_storerinew_pcr", 0);
		dot_new_producers.put("S2_storerbnew_pi", 0);
		dot_new_producers.put("S4_storerbnew_ap", 0);
		dot_new_producers.put("S2_storerbnew_pr", 0);
		dot_new_producers.put("S2_storerbnew_pbr", 0);
		dot_new_producers.put("S2_storerbnew_pci", 0);
		dot_new_producers.put("S2_storerbnew_pcr", 0);
		dot_new_producers.put("S2_storerhnew_pi", 0);
		dot_new_producers.put("S4_storerhnew_ap", 0);
		dot_new_producers.put("S2_storerhnew_pr", 0);
		dot_new_producers.put("S2_storerhnew_pbr", 0);
		dot_new_producers.put("S2_storerhnew_pci", 0);
		dot_new_producers.put("S2_storerhnew_pcr", 0);
		dot_new_producers.put("S2_allocframe", 0);
		dot_new_producers.put("L2_loadw_locked", 0);
		dot_new_producers.put("L4_loadw_phys", 0);
		dot_new_producers.put("L4_loadrub_rr", 0);
		dot_new_producers.put("L2_ploadrubt_io", 0);
		dot_new_producers.put("L2_ploadrubt_pi", 0);
		dot_new_producers.put("L2_ploadrubf_io", 0);
		dot_new_producers.put("L2_ploadrubf_pi", 0);
		dot_new_producers.put("L2_ploadrubtnew_io", 0);
		dot_new_producers.put("L2_ploadrubfnew_io", 0);
		dot_new_producers.put("L4_ploadrubt_rr", 0);
		dot_new_producers.put("L4_ploadrubf_rr", 0);
		dot_new_producers.put("L4_ploadrubtnew_rr", 0);
		dot_new_producers.put("L4_ploadrubfnew_rr", 0);
		dot_new_producers.put("L2_ploadrubtnew_pi", 0);
		dot_new_producers.put("L2_ploadrubfnew_pi", 0);
		dot_new_producers.put("L4_ploadrubt_abs", 0);
		dot_new_producers.put("L4_ploadrubf_abs", 0);
		dot_new_producers.put("L4_ploadrubtnew_abs", 0);
		dot_new_producers.put("L4_ploadrubfnew_abs", 0);
		dot_new_producers.put("L4_loadrb_rr", 0);
		dot_new_producers.put("L2_ploadrbt_io", 0);
		dot_new_producers.put("L2_ploadrbt_pi", 0);
		dot_new_producers.put("L2_ploadrbf_io", 0);
		dot_new_producers.put("L2_ploadrbf_pi", 0);
		dot_new_producers.put("L2_ploadrbtnew_io", 0);
		dot_new_producers.put("L2_ploadrbfnew_io", 0);
		dot_new_producers.put("L4_ploadrbt_rr", 0);
		dot_new_producers.put("L4_ploadrbf_rr", 0);
		dot_new_producers.put("L4_ploadrbtnew_rr", 0);
		dot_new_producers.put("L4_ploadrbfnew_rr", 0);
		dot_new_producers.put("L2_ploadrbtnew_pi", 0);
		dot_new_producers.put("L2_ploadrbfnew_pi", 0);
		dot_new_producers.put("L4_ploadrbt_abs", 0);
		dot_new_producers.put("L4_ploadrbf_abs", 0);
		dot_new_producers.put("L4_ploadrbtnew_abs", 0);
		dot_new_producers.put("L4_ploadrbfnew_abs", 0);
		dot_new_producers.put("L4_loadruh_rr", 0);
		dot_new_producers.put("L2_ploadruht_io", 0);
		dot_new_producers.put("L2_ploadruht_pi", 0);
		dot_new_producers.put("L2_ploadruhf_io", 0);
		dot_new_producers.put("L2_ploadruhf_pi", 0);
		dot_new_producers.put("L2_ploadruhtnew_io", 0);
		dot_new_producers.put("L2_ploadruhfnew_io", 0);
		dot_new_producers.put("L4_ploadruht_rr", 0);
		dot_new_producers.put("L4_ploadruhf_rr", 0);
		dot_new_producers.put("L4_ploadruhtnew_rr", 0);
		dot_new_producers.put("L4_ploadruhfnew_rr", 0);
		dot_new_producers.put("L2_ploadruhtnew_pi", 0);
		dot_new_producers.put("L2_ploadruhfnew_pi", 0);
		dot_new_producers.put("L4_ploadruht_abs", 0);
		dot_new_producers.put("L4_ploadruhf_abs", 0);
		dot_new_producers.put("L4_ploadruhtnew_abs", 0);
		dot_new_producers.put("L4_ploadruhfnew_abs", 0);
		dot_new_producers.put("L4_loadrh_rr", 0);
		dot_new_producers.put("L2_ploadrht_io", 0);
		dot_new_producers.put("L2_ploadrht_pi", 0);
		dot_new_producers.put("L2_ploadrhf_io", 0);
		dot_new_producers.put("L2_ploadrhf_pi", 0);
		dot_new_producers.put("L2_ploadrhtnew_io", 0);
		dot_new_producers.put("L2_ploadrhfnew_io", 0);
		dot_new_producers.put("L4_ploadrht_rr", 0);
		dot_new_producers.put("L4_ploadrhf_rr", 0);
		dot_new_producers.put("L4_ploadrhtnew_rr", 0);
		dot_new_producers.put("L4_ploadrhfnew_rr", 0);
		dot_new_producers.put("L2_ploadrhtnew_pi", 0);
		dot_new_producers.put("L2_ploadrhfnew_pi", 0);
		dot_new_producers.put("L4_ploadrht_abs", 0);
		dot_new_producers.put("L4_ploadrhf_abs", 0);
		dot_new_producers.put("L4_ploadrhtnew_abs", 0);
		dot_new_producers.put("L4_ploadrhfnew_abs", 0);
		dot_new_producers.put("L4_loadri_rr", 0);
		dot_new_producers.put("L2_ploadrit_io", 0);
		dot_new_producers.put("L2_ploadrit_pi", 0);
		dot_new_producers.put("L2_ploadrif_io", 0);
		dot_new_producers.put("L2_ploadrif_pi", 0);
		dot_new_producers.put("L2_ploadritnew_io", 0);
		dot_new_producers.put("L2_ploadrifnew_io", 0);
		dot_new_producers.put("L4_ploadrit_rr", 0);
		dot_new_producers.put("L4_ploadrif_rr", 0);
		dot_new_producers.put("L4_ploadritnew_rr", 0);
		dot_new_producers.put("L4_ploadrifnew_rr", 0);
		dot_new_producers.put("L2_ploadritnew_pi", 0);
		dot_new_producers.put("L2_ploadrifnew_pi", 0);
		dot_new_producers.put("L4_ploadrit_abs", 0);
		dot_new_producers.put("L4_ploadrif_abs", 0);
		dot_new_producers.put("L4_ploadritnew_abs", 0);
		dot_new_producers.put("L4_ploadrifnew_abs", 0);
		dot_new_producers.put("L2_ploadrdt_pi", 1);
		dot_new_producers.put("L2_ploadrdf_pi", 1);
		dot_new_producers.put("L2_ploadrdtnew_pi", 1);
		dot_new_producers.put("L2_ploadrdfnew_pi", 1);
		dot_new_producers.put("S2_pstorerbt_pi", 0);
		dot_new_producers.put("S2_pstorerbf_pi", 0);
		dot_new_producers.put("S2_pstorerbtnew_pi", 0);
		dot_new_producers.put("S2_pstorerbfnew_pi", 0);
		dot_new_producers.put("S2_pstorerht_pi", 0);
		dot_new_producers.put("S2_pstorerhf_pi", 0);
		dot_new_producers.put("S2_pstorerhtnew_pi", 0);
		dot_new_producers.put("S2_pstorerhfnew_pi", 0);
		dot_new_producers.put("S2_pstorerft_pi", 0);
		dot_new_producers.put("S2_pstorerff_pi", 0);
		dot_new_producers.put("S2_pstorerftnew_pi", 0);
		dot_new_producers.put("S2_pstorerffnew_pi", 0);
		dot_new_producers.put("S2_pstorerit_pi", 0);
		dot_new_producers.put("S2_pstorerif_pi", 0);
		dot_new_producers.put("S2_pstoreritnew_pi", 0);
		dot_new_producers.put("S2_pstorerifnew_pi", 0);
		dot_new_producers.put("S2_pstorerdt_pi", 0);
		dot_new_producers.put("S2_pstorerdf_pi", 0);
		dot_new_producers.put("S2_pstorerdtnew_pi", 0);
		dot_new_producers.put("S2_pstorerdfnew_pi", 0);
		dot_new_producers.put("S2_pstorerinewt_pi", 0);
		dot_new_producers.put("S2_pstorerinewf_pi", 0);
		dot_new_producers.put("S2_pstorerinewtnew_pi", 0);
		dot_new_producers.put("S2_pstorerinewfnew_pi", 0);
		dot_new_producers.put("S2_pstorerbnewt_pi", 0);
		dot_new_producers.put("S2_pstorerbnewf_pi", 0);
		dot_new_producers.put("S2_pstorerbnewtnew_pi", 0);
		dot_new_producers.put("S2_pstorerbnewfnew_pi", 0);
		dot_new_producers.put("S2_pstorerhnewt_pi", 0);
		dot_new_producers.put("S2_pstorerhnewf_pi", 0);
		dot_new_producers.put("S2_pstorerhnewtnew_pi", 0);
		dot_new_producers.put("S2_pstorerhnewfnew_pi", 0);
		dot_new_producers.put("L2_loadrubgp", 0);
		dot_new_producers.put("L2_loadrbgp", 0);
		dot_new_producers.put("L2_loadruhgp", 0);
		dot_new_producers.put("L2_loadrhgp", 0);
		dot_new_producers.put("L2_loadrigp", 0);
		dot_new_producers.put("A4_rcmpeqi", 0);
		dot_new_producers.put("A4_rcmpneqi", 0);
		dot_new_producers.put("A4_rcmpeq", 0);
		dot_new_producers.put("A4_rcmpneq", 0);
		dot_new_producers.put("C2_vitpack", 0);
		dot_new_producers.put("C2_mux", 0);
		dot_new_producers.put("C2_cmovenewit", 0);
		dot_new_producers.put("C2_cmovenewif", 0);
		dot_new_producers.put("C2_cmoveit", 0);
		dot_new_producers.put("C2_cmoveif", 0);
		dot_new_producers.put("C2_muxii", 0);
		dot_new_producers.put("C2_muxir", 0);
		dot_new_producers.put("C2_muxri", 0);
		dot_new_producers.put("C2_tfrpr", 0);
		dot_new_producers.put("M2_mpy_acc_hh_s0", 0);
		dot_new_producers.put("M2_mpy_acc_hh_s1", 0);
		dot_new_producers.put("M2_mpy_acc_hl_s0", 0);
		dot_new_producers.put("M2_mpy_acc_hl_s1", 0);
		dot_new_producers.put("M2_mpy_acc_lh_s0", 0);
		dot_new_producers.put("M2_mpy_acc_lh_s1", 0);
		dot_new_producers.put("M2_mpy_acc_ll_s0", 0);
		dot_new_producers.put("M2_mpy_acc_ll_s1", 0);
		dot_new_producers.put("M2_mpy_nac_hh_s0", 0);
		dot_new_producers.put("M2_mpy_nac_hh_s1", 0);
		dot_new_producers.put("M2_mpy_nac_hl_s0", 0);
		dot_new_producers.put("M2_mpy_nac_hl_s1", 0);
		dot_new_producers.put("M2_mpy_nac_lh_s0", 0);
		dot_new_producers.put("M2_mpy_nac_lh_s1", 0);
		dot_new_producers.put("M2_mpy_nac_ll_s0", 0);
		dot_new_producers.put("M2_mpy_nac_ll_s1", 0);
		dot_new_producers.put("M2_mpy_acc_sat_hh_s0", 0);
		dot_new_producers.put("M2_mpy_acc_sat_hh_s1", 0);
		dot_new_producers.put("M2_mpy_acc_sat_hl_s0", 0);
		dot_new_producers.put("M2_mpy_acc_sat_hl_s1", 0);
		dot_new_producers.put("M2_mpy_acc_sat_lh_s0", 0);
		dot_new_producers.put("M2_mpy_acc_sat_lh_s1", 0);
		dot_new_producers.put("M2_mpy_acc_sat_ll_s0", 0);
		dot_new_producers.put("M2_mpy_acc_sat_ll_s1", 0);
		dot_new_producers.put("M2_mpy_nac_sat_hh_s0", 0);
		dot_new_producers.put("M2_mpy_nac_sat_hh_s1", 0);
		dot_new_producers.put("M2_mpy_nac_sat_hl_s0", 0);
		dot_new_producers.put("M2_mpy_nac_sat_hl_s1", 0);
		dot_new_producers.put("M2_mpy_nac_sat_lh_s0", 0);
		dot_new_producers.put("M2_mpy_nac_sat_lh_s1", 0);
		dot_new_producers.put("M2_mpy_nac_sat_ll_s0", 0);
		dot_new_producers.put("M2_mpy_nac_sat_ll_s1", 0);
		dot_new_producers.put("M2_mpy_hh_s0", 0);
		dot_new_producers.put("M2_mpy_hh_s1", 0);
		dot_new_producers.put("M2_mpy_hl_s0", 0);
		dot_new_producers.put("M2_mpy_hl_s1", 0);
		dot_new_producers.put("M2_mpy_lh_s0", 0);
		dot_new_producers.put("M2_mpy_lh_s1", 0);
		dot_new_producers.put("M2_mpy_ll_s0", 0);
		dot_new_producers.put("M2_mpy_ll_s1", 0);
		dot_new_producers.put("M2_mpy_sat_hh_s0", 0);
		dot_new_producers.put("M2_mpy_sat_hh_s1", 0);
		dot_new_producers.put("M2_mpy_sat_hl_s0", 0);
		dot_new_producers.put("M2_mpy_sat_hl_s1", 0);
		dot_new_producers.put("M2_mpy_sat_lh_s0", 0);
		dot_new_producers.put("M2_mpy_sat_lh_s1", 0);
		dot_new_producers.put("M2_mpy_sat_ll_s0", 0);
		dot_new_producers.put("M2_mpy_sat_ll_s1", 0);
		dot_new_producers.put("M2_mpy_rnd_hh_s0", 0);
		dot_new_producers.put("M2_mpy_rnd_hh_s1", 0);
		dot_new_producers.put("M2_mpy_rnd_hl_s0", 0);
		dot_new_producers.put("M2_mpy_rnd_hl_s1", 0);
		dot_new_producers.put("M2_mpy_rnd_lh_s0", 0);
		dot_new_producers.put("M2_mpy_rnd_lh_s1", 0);
		dot_new_producers.put("M2_mpy_rnd_ll_s0", 0);
		dot_new_producers.put("M2_mpy_rnd_ll_s1", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_hh_s0", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_hh_s1", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_hl_s0", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_hl_s1", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_lh_s0", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_lh_s1", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_ll_s0", 0);
		dot_new_producers.put("M2_mpy_sat_rnd_ll_s1", 0);
		dot_new_producers.put("M2_mpyu_acc_hh_s0", 0);
		dot_new_producers.put("M2_mpyu_acc_hh_s1", 0);
		dot_new_producers.put("M2_mpyu_acc_hl_s0", 0);
		dot_new_producers.put("M2_mpyu_acc_hl_s1", 0);
		dot_new_producers.put("M2_mpyu_acc_lh_s0", 0);
		dot_new_producers.put("M2_mpyu_acc_lh_s1", 0);
		dot_new_producers.put("M2_mpyu_acc_ll_s0", 0);
		dot_new_producers.put("M2_mpyu_acc_ll_s1", 0);
		dot_new_producers.put("M2_mpyu_nac_hh_s0", 0);
		dot_new_producers.put("M2_mpyu_nac_hh_s1", 0);
		dot_new_producers.put("M2_mpyu_nac_hl_s0", 0);
		dot_new_producers.put("M2_mpyu_nac_hl_s1", 0);
		dot_new_producers.put("M2_mpyu_nac_lh_s0", 0);
		dot_new_producers.put("M2_mpyu_nac_lh_s1", 0);
		dot_new_producers.put("M2_mpyu_nac_ll_s0", 0);
		dot_new_producers.put("M2_mpyu_nac_ll_s1", 0);
		dot_new_producers.put("M2_mpyu_hh_s0", 0);
		dot_new_producers.put("M2_mpyu_hh_s1", 0);
		dot_new_producers.put("M2_mpyu_hl_s0", 0);
		dot_new_producers.put("M2_mpyu_hl_s1", 0);
		dot_new_producers.put("M2_mpyu_lh_s0", 0);
		dot_new_producers.put("M2_mpyu_lh_s1", 0);
		dot_new_producers.put("M2_mpyu_ll_s0", 0);
		dot_new_producers.put("M2_mpyu_ll_s1", 0);
		dot_new_producers.put("M2_mpysip", 0);
		dot_new_producers.put("M2_mpysin", 0);
		dot_new_producers.put("M2_macsip", 0);
		dot_new_producers.put("M2_macsin", 0);
		dot_new_producers.put("M2_mpy_up", 0);
		dot_new_producers.put("M2_mpy_up_s1", 0);
		dot_new_producers.put("M2_mpy_up_s1_sat", 0);
		dot_new_producers.put("M2_mpyu_up", 0);
		dot_new_producers.put("M2_mpysu_up", 0);
		dot_new_producers.put("M2_dpmpyss_rnd_s0", 0);
		dot_new_producers.put("M4_mac_up_s1_sat", 0);
		dot_new_producers.put("M4_nac_up_s1_sat", 0);
		dot_new_producers.put("M2_mpyi", 0);
		dot_new_producers.put("M2_maci", 0);
		dot_new_producers.put("M2_mnaci", 0);
		dot_new_producers.put("M2_acci", 0);
		dot_new_producers.put("M2_accii", 0);
		dot_new_producers.put("M2_nacci", 0);
		dot_new_producers.put("M2_naccii", 0);
		dot_new_producers.put("M2_subacc", 0);
		dot_new_producers.put("M4_mpyrr_addr", 0);
		dot_new_producers.put("M4_mpyri_addr_u2", 0);
		dot_new_producers.put("M4_mpyri_addr", 0);
		dot_new_producers.put("M4_mpyri_addi", 0);
		dot_new_producers.put("M4_mpyrr_addi", 0);
		dot_new_producers.put("M2_vmpy2s_s0pack", 0);
		dot_new_producers.put("M2_vmpy2s_s1pack", 0);
		dot_new_producers.put("M2_vdmpyrs_s0", 0);
		dot_new_producers.put("M2_vdmpyrs_s1", 0);
		dot_new_producers.put("M2_cmpyrs_s0", 0);
		dot_new_producers.put("M2_cmpyrs_s1", 0);
		dot_new_producers.put("M2_cmpyrsc_s0", 0);
		dot_new_producers.put("M2_cmpyrsc_s1", 0);
		dot_new_producers.put("M2_vrcmpys_s1rp_h", 0);
		dot_new_producers.put("M2_vrcmpys_s1rp_l", 0);
		dot_new_producers.put("M2_hmmpyl_rs1", 0);
		dot_new_producers.put("M2_hmmpyh_rs1", 0);
		dot_new_producers.put("M2_hmmpyl_s1", 0);
		dot_new_producers.put("M2_hmmpyh_s1", 0);
		dot_new_producers.put("M4_cmpyi_wh", 0);
		dot_new_producers.put("M4_cmpyr_wh", 0);
		dot_new_producers.put("M4_cmpyi_whc", 0);
		dot_new_producers.put("M4_cmpyr_whc", 0);
		dot_new_producers.put("M7_wcmpyrw", 0);
		dot_new_producers.put("M7_wcmpyrwc", 0);
		dot_new_producers.put("M7_wcmpyiw", 0);
		dot_new_producers.put("M7_wcmpyiwc", 0);
		dot_new_producers.put("M7_wcmpyrw_rnd", 0);
		dot_new_producers.put("M7_wcmpyrwc_rnd", 0);
		dot_new_producers.put("M7_wcmpyiw_rnd", 0);
		dot_new_producers.put("M7_wcmpyiwc_rnd", 0);
		dot_new_producers.put("A2_add", 0);
		dot_new_producers.put("A2_sub", 0);
		dot_new_producers.put("A2_paddt", 0);
		dot_new_producers.put("A2_paddf", 0);
		dot_new_producers.put("A2_paddtnew", 0);
		dot_new_producers.put("A2_paddfnew", 0);
		dot_new_producers.put("A2_psubt", 0);
		dot_new_producers.put("A2_psubf", 0);
		dot_new_producers.put("A2_psubtnew", 0);
		dot_new_producers.put("A2_psubfnew", 0);
		dot_new_producers.put("A2_paddit", 0);
		dot_new_producers.put("A2_paddif", 0);
		dot_new_producers.put("A2_padditnew", 0);
		dot_new_producers.put("A2_paddifnew", 0);
		dot_new_producers.put("A2_pxort", 0);
		dot_new_producers.put("A2_pxorf", 0);
		dot_new_producers.put("A2_pxortnew", 0);
		dot_new_producers.put("A2_pxorfnew", 0);
		dot_new_producers.put("A2_pandt", 0);
		dot_new_producers.put("A2_pandf", 0);
		dot_new_producers.put("A2_pandtnew", 0);
		dot_new_producers.put("A2_pandfnew", 0);
		dot_new_producers.put("A2_port", 0);
		dot_new_producers.put("A2_porf", 0);
		dot_new_producers.put("A2_portnew", 0);
		dot_new_producers.put("A2_porfnew", 0);
		dot_new_producers.put("A4_psxtbt", 0);
		dot_new_producers.put("A4_psxtbf", 0);
		dot_new_producers.put("A4_psxtbtnew", 0);
		dot_new_producers.put("A4_psxtbfnew", 0);
		dot_new_producers.put("A4_pzxtbt", 0);
		dot_new_producers.put("A4_pzxtbf", 0);
		dot_new_producers.put("A4_pzxtbtnew", 0);
		dot_new_producers.put("A4_pzxtbfnew", 0);
		dot_new_producers.put("A4_psxtht", 0);
		dot_new_producers.put("A4_psxthf", 0);
		dot_new_producers.put("A4_psxthtnew", 0);
		dot_new_producers.put("A4_psxthfnew", 0);
		dot_new_producers.put("A4_pzxtht", 0);
		dot_new_producers.put("A4_pzxthf", 0);
		dot_new_producers.put("A4_pzxthtnew", 0);
		dot_new_producers.put("A4_pzxthfnew", 0);
		dot_new_producers.put("A4_paslht", 0);
		dot_new_producers.put("A4_paslhf", 0);
		dot_new_producers.put("A4_paslhtnew", 0);
		dot_new_producers.put("A4_paslhfnew", 0);
		dot_new_producers.put("A4_pasrht", 0);
		dot_new_producers.put("A4_pasrhf", 0);
		dot_new_producers.put("A4_pasrhtnew", 0);
		dot_new_producers.put("A4_pasrhfnew", 0);
		dot_new_producers.put("A2_addsat", 0);
		dot_new_producers.put("A2_subsat", 0);
		dot_new_producers.put("A2_addi", 0);
		dot_new_producers.put("C4_addipc", 0);
		dot_new_producers.put("A2_addh_l16_ll", 0);
		dot_new_producers.put("A2_addh_l16_hl", 0);
		dot_new_producers.put("A2_addh_l16_sat_ll", 0);
		dot_new_producers.put("A2_addh_l16_sat_hl", 0);
		dot_new_producers.put("A2_subh_l16_ll", 0);
		dot_new_producers.put("A2_subh_l16_hl", 0);
		dot_new_producers.put("A2_subh_l16_sat_ll", 0);
		dot_new_producers.put("A2_subh_l16_sat_hl", 0);
		dot_new_producers.put("A2_addh_h16_ll", 0);
		dot_new_producers.put("A2_addh_h16_lh", 0);
		dot_new_producers.put("A2_addh_h16_hl", 0);
		dot_new_producers.put("A2_addh_h16_hh", 0);
		dot_new_producers.put("A2_addh_h16_sat_ll", 0);
		dot_new_producers.put("A2_addh_h16_sat_lh", 0);
		dot_new_producers.put("A2_addh_h16_sat_hl", 0);
		dot_new_producers.put("A2_addh_h16_sat_hh", 0);
		dot_new_producers.put("A2_subh_h16_ll", 0);
		dot_new_producers.put("A2_subh_h16_lh", 0);
		dot_new_producers.put("A2_subh_h16_hl", 0);
		dot_new_producers.put("A2_subh_h16_hh", 0);
		dot_new_producers.put("A2_subh_h16_sat_ll", 0);
		dot_new_producers.put("A2_subh_h16_sat_lh", 0);
		dot_new_producers.put("A2_subh_h16_sat_hl", 0);
		dot_new_producers.put("A2_subh_h16_sat_hh", 0);
		dot_new_producers.put("A2_aslh", 0);
		dot_new_producers.put("A2_asrh", 0);
		dot_new_producers.put("A2_negsat", 0);
		dot_new_producers.put("A2_abs", 0);
		dot_new_producers.put("A2_abssat", 0);
		dot_new_producers.put("A2_max", 0);
		dot_new_producers.put("A2_maxu", 0);
		dot_new_producers.put("A2_min", 0);
		dot_new_producers.put("A2_minu", 0);
		dot_new_producers.put("A2_tfr", 0);
		dot_new_producers.put("A2_tfrsi", 0);
		dot_new_producers.put("A2_sxtb", 0);
		dot_new_producers.put("A2_zxth", 0);
		dot_new_producers.put("A2_sxth", 0);
		dot_new_producers.put("A2_combine_hh", 0);
		dot_new_producers.put("A2_combine_hl", 0);
		dot_new_producers.put("A2_combine_lh", 0);
		dot_new_producers.put("A2_combine_ll", 0);
		dot_new_producers.put("A2_tfril", 0);
		dot_new_producers.put("A2_tfrih", 0);
		dot_new_producers.put("A2_tfrcrr", 0);
		dot_new_producers.put("A2_and", 0);
		dot_new_producers.put("A2_or", 0);
		dot_new_producers.put("A2_xor", 0);
		dot_new_producers.put("M2_xor_xacc", 0);
		dot_new_producers.put("A4_andn", 0);
		dot_new_producers.put("A4_orn", 0);
		dot_new_producers.put("S4_addaddi", 0);
		dot_new_producers.put("S4_subaddi", 0);
		dot_new_producers.put("M4_and_and", 0);
		dot_new_producers.put("M4_and_andn", 0);
		dot_new_producers.put("M4_and_or", 0);
		dot_new_producers.put("M4_and_xor", 0);
		dot_new_producers.put("M4_or_and", 0);
		dot_new_producers.put("M4_or_andn", 0);
		dot_new_producers.put("M4_or_or", 0);
		dot_new_producers.put("M4_or_xor", 0);
		dot_new_producers.put("S4_or_andix", 0);
		dot_new_producers.put("S4_or_andi", 0);
		dot_new_producers.put("S4_or_ori", 0);
		dot_new_producers.put("M4_xor_and", 0);
		dot_new_producers.put("M4_xor_or", 0);
		dot_new_producers.put("M4_xor_andn", 0);
		dot_new_producers.put("A2_subri", 0);
		dot_new_producers.put("A2_andir", 0);
		dot_new_producers.put("A2_orir", 0);
		dot_new_producers.put("A2_sat", 0);
		dot_new_producers.put("A2_roundsat", 0);
		dot_new_producers.put("A2_sath", 0);
		dot_new_producers.put("A2_satuh", 0);
		dot_new_producers.put("A2_satub", 0);
		dot_new_producers.put("A2_satb", 0);
		dot_new_producers.put("A5_vaddhubs", 0);
		dot_new_producers.put("A2_svavgh", 0);
		dot_new_producers.put("A2_svavghs", 0);
		dot_new_producers.put("A2_svnavgh", 0);
		dot_new_producers.put("A2_svaddh", 0);
		dot_new_producers.put("A2_svaddhs", 0);
		dot_new_producers.put("A2_svadduhs", 0);
		dot_new_producers.put("A2_svsubh", 0);
		dot_new_producers.put("A2_svsubhs", 0);
		dot_new_producers.put("A2_svsubuhs", 0);
		dot_new_producers.put("M2_vraddh", 0);
		dot_new_producers.put("M2_vradduh", 0);
		dot_new_producers.put("A4_round_ri", 0);
		dot_new_producers.put("A4_round_rr", 0);
		dot_new_producers.put("A4_round_ri_sat", 0);
		dot_new_producers.put("A4_round_rr_sat", 0);
		dot_new_producers.put("A4_cround_ri", 0);
		dot_new_producers.put("A4_cround_rr", 0);
		dot_new_producers.put("A7_clip", 0);
		dot_new_producers.put("A4_modwrapu", 0);
		dot_new_producers.put("F2_sfadd", 0);
		dot_new_producers.put("F2_sfsub", 0);
		dot_new_producers.put("F2_sfmpy", 0);
		dot_new_producers.put("F2_sffma", 0);
		dot_new_producers.put("F2_sffma_sc", 0);
		dot_new_producers.put("F2_sffms", 0);
		dot_new_producers.put("F2_sffma_lib", 0);
		dot_new_producers.put("F2_sffms_lib", 0);
		dot_new_producers.put("F2_sfmax", 0);
		dot_new_producers.put("F2_sfmin", 0);
		dot_new_producers.put("F2_sfimm_p", 0);
		dot_new_producers.put("F2_sfimm_n", 0);
		dot_new_producers.put("F2_sfrecipa", 0);
		dot_new_producers.put("F2_sffixupn", 0);
		dot_new_producers.put("F2_sffixupd", 0);
		dot_new_producers.put("F2_sfinvsqrta", 0);
		dot_new_producers.put("F2_sffixupr", 0);
		dot_new_producers.put("F2_conv_df2sf", 0);
		dot_new_producers.put("F2_conv_uw2sf", 0);
		dot_new_producers.put("F2_conv_w2sf", 0);
		dot_new_producers.put("F2_conv_ud2sf", 0);
		dot_new_producers.put("F2_conv_d2sf", 0);
		dot_new_producers.put("F2_conv_sf2uw", 0);
		dot_new_producers.put("F2_conv_sf2w", 0);
		dot_new_producers.put("F2_conv_df2uw", 0);
		dot_new_producers.put("F2_conv_df2w", 0);
		dot_new_producers.put("F2_conv_sf2uw_chop", 0);
		dot_new_producers.put("F2_conv_sf2w_chop", 0);
		dot_new_producers.put("F2_conv_df2uw_chop", 0);
		dot_new_producers.put("F2_conv_df2w_chop", 0);
		dot_new_producers.put("S2_asr_r_r", 0);
		dot_new_producers.put("S2_asl_r_r", 0);
		dot_new_producers.put("S2_lsr_r_r", 0);
		dot_new_producers.put("S2_lsl_r_r", 0);
		dot_new_producers.put("S2_asr_r_r_acc", 0);
		dot_new_producers.put("S2_asl_r_r_acc", 0);
		dot_new_producers.put("S2_lsr_r_r_acc", 0);
		dot_new_producers.put("S2_lsl_r_r_acc", 0);
		dot_new_producers.put("S2_asr_r_r_nac", 0);
		dot_new_producers.put("S2_asl_r_r_nac", 0);
		dot_new_producers.put("S2_lsr_r_r_nac", 0);
		dot_new_producers.put("S2_lsl_r_r_nac", 0);
		dot_new_producers.put("S2_asr_r_r_and", 0);
		dot_new_producers.put("S2_asl_r_r_and", 0);
		dot_new_producers.put("S2_lsr_r_r_and", 0);
		dot_new_producers.put("S2_lsl_r_r_and", 0);
		dot_new_producers.put("S2_asr_r_r_or", 0);
		dot_new_producers.put("S2_asl_r_r_or", 0);
		dot_new_producers.put("S2_lsr_r_r_or", 0);
		dot_new_producers.put("S2_lsl_r_r_or", 0);
		dot_new_producers.put("S2_asr_r_r_sat", 0);
		dot_new_producers.put("S2_asl_r_r_sat", 0);
		dot_new_producers.put("S2_asr_i_r", 0);
		dot_new_producers.put("S2_lsr_i_r", 0);
		dot_new_producers.put("S2_asl_i_r", 0);
		dot_new_producers.put("S6_rol_i_r", 0);
		dot_new_producers.put("S2_asr_i_r_acc", 0);
		dot_new_producers.put("S2_lsr_i_r_acc", 0);
		dot_new_producers.put("S2_asl_i_r_acc", 0);
		dot_new_producers.put("S6_rol_i_r_acc", 0);
		dot_new_producers.put("S2_asr_i_r_nac", 0);
		dot_new_producers.put("S2_lsr_i_r_nac", 0);
		dot_new_producers.put("S2_asl_i_r_nac", 0);
		dot_new_producers.put("S6_rol_i_r_nac", 0);
		dot_new_producers.put("S2_lsr_i_r_xacc", 0);
		dot_new_producers.put("S2_asl_i_r_xacc", 0);
		dot_new_producers.put("S6_rol_i_r_xacc", 0);
		dot_new_producers.put("S2_asr_i_r_and", 0);
		dot_new_producers.put("S2_lsr_i_r_and", 0);
		dot_new_producers.put("S2_asl_i_r_and", 0);
		dot_new_producers.put("S6_rol_i_r_and", 0);
		dot_new_producers.put("S2_asr_i_r_or", 0);
		dot_new_producers.put("S2_lsr_i_r_or", 0);
		dot_new_producers.put("S2_asl_i_r_or", 0);
		dot_new_producers.put("S6_rol_i_r_or", 0);
		dot_new_producers.put("S2_asl_i_r_sat", 0);
		dot_new_producers.put("S2_asr_i_r_rnd", 0);
		dot_new_producers.put("S4_lsli", 0);
		dot_new_producers.put("S2_addasl_rrri", 0);
		dot_new_producers.put("S4_andi_asl_ri", 0);
		dot_new_producers.put("S4_ori_asl_ri", 0);
		dot_new_producers.put("S4_addi_asl_ri", 0);
		dot_new_producers.put("S4_subi_asl_ri", 0);
		dot_new_producers.put("S4_andi_lsr_ri", 0);
		dot_new_producers.put("S4_ori_lsr_ri", 0);
		dot_new_producers.put("S4_addi_lsr_ri", 0);
		dot_new_producers.put("S4_subi_lsr_ri", 0);
		dot_new_producers.put("S2_vsplatrb", 0);
		dot_new_producers.put("S2_insert", 0);
		dot_new_producers.put("S2_tableidxb", 0);
		dot_new_producers.put("S2_tableidxh", 0);
		dot_new_producers.put("S2_tableidxw", 0);
		dot_new_producers.put("S2_tableidxd", 0);
		dot_new_producers.put("S4_extract", 0);
		dot_new_producers.put("S2_extractu", 0);
		dot_new_producers.put("S2_mask", 0);
		dot_new_producers.put("S2_insert_rp", 0);
		dot_new_producers.put("S4_extract_rp", 0);
		dot_new_producers.put("S2_extractu_rp", 0);
		dot_new_producers.put("S2_setbit_i", 0);
		dot_new_producers.put("S2_togglebit_i", 0);
		dot_new_producers.put("S2_clrbit_i", 0);
		dot_new_producers.put("S2_setbit_r", 0);
		dot_new_producers.put("S2_togglebit_r", 0);
		dot_new_producers.put("S2_clrbit_r", 0);
		dot_new_producers.put("S5_asrhub_rnd_sat", 0);
		dot_new_producers.put("S5_asrhub_sat", 0);
		dot_new_producers.put("S2_asr_i_svw_trun", 0);
		dot_new_producers.put("S2_asr_r_svw_trun", 0);
		dot_new_producers.put("S2_vrndpackwh", 0);
		dot_new_producers.put("S2_vrndpackwhs", 0);
		dot_new_producers.put("S2_vsathub", 0);
		dot_new_producers.put("S2_svsathub", 0);
		dot_new_producers.put("S2_svsathb", 0);
		dot_new_producers.put("S2_vsathb", 0);
		dot_new_producers.put("S2_vtrunohb", 0);
		dot_new_producers.put("S2_vtrunehb", 0);
		dot_new_producers.put("S2_vsatwh", 0);
		dot_new_producers.put("S2_vsatwuh", 0);
		dot_new_producers.put("A2_swiz", 0);
		dot_new_producers.put("S5_popcountp", 0);
		dot_new_producers.put("S4_parity", 0);
		dot_new_producers.put("S2_parityp", 0);
		dot_new_producers.put("S2_clbnorm", 0);
		dot_new_producers.put("S4_clbaddi", 0);
		dot_new_producers.put("S4_clbpnorm", 0);
		dot_new_producers.put("S4_clbpaddi", 0);
		dot_new_producers.put("S2_clb", 0);
		dot_new_producers.put("S2_cl0", 0);
		dot_new_producers.put("S2_cl1", 0);
		dot_new_producers.put("S2_clbp", 0);
		dot_new_producers.put("S2_cl0p", 0);
		dot_new_producers.put("S2_cl1p", 0);
		dot_new_producers.put("S2_brev", 0);
		dot_new_producers.put("S2_ct0", 0);
		dot_new_producers.put("S2_ct1", 0);
		dot_new_producers.put("S2_ct0p", 0);
		dot_new_producers.put("S2_ct1p", 0);
		dot_new_producers.put("J2_trap1", 0);
		dot_new_producers.put("Y2_iassignr", 0);
		dot_new_producers.put("Y2_getimask", 0);
		dot_new_producers.put("Y5_ctlbw", 0);
		dot_new_producers.put("Y5_tlboc", 0);
		dot_new_producers.put("Y2_tlbp", 0);
		dot_new_producers.put("Y2_crswap0", 0);
		dot_new_producers.put("Y4_crswap1", 0);
		dot_new_producers.put("Y2_tfrscrr", 0);
		dot_new_producers.put("G4_tfrgcrr", 0);
		dot_new_producers.put("Y2_ictagr", 0);
		dot_new_producers.put("Y2_icdatar", 0);
		dot_new_producers.put("Y2_dctagr", 0);
		dot_new_producers.put("Y4_l2tagr", 0);
	}

	private static final Map<String, Integer> dot_new_operands;

	static {
		dot_new_operands = new HashMap<>();
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqi_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqi_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgti_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgti_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgti_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgti_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtui_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtui_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqn1_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeqn1_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtn1_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtn1_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_tstbit0_t_jumpnv_t", 0);
		dot_new_operands.put("J4_tstbit0_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_tstbit0_f_jumpnv_t", 0);
		dot_new_operands.put("J4_tstbit0_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpeq_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeq_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgt_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgt_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtu_t_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmplt_t_jumpnv_t", 1);
		dot_new_operands.put("J4_cmplt_t_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpltu_t_jumpnv_t", 1);
		dot_new_operands.put("J4_cmpltu_t_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpeq_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpeq_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgt_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgt_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_t", 0);
		dot_new_operands.put("J4_cmpgtu_f_jumpnv_nt", 0);
		dot_new_operands.put("J4_cmplt_f_jumpnv_t", 1);
		dot_new_operands.put("J4_cmplt_f_jumpnv_nt", 1);
		dot_new_operands.put("J4_cmpltu_f_jumpnv_t", 1);
		dot_new_operands.put("J4_cmpltu_f_jumpnv_nt", 1);
		dot_new_operands.put("S2_storerinew_io", 1);
		dot_new_operands.put("S2_storerinew_pi", 1);
		dot_new_operands.put("S4_storerinew_ap", 1);
		dot_new_operands.put("S2_storerinew_pr", 2);
		dot_new_operands.put("S4_storerinew_ur", 1);
		dot_new_operands.put("S2_storerinew_pbr", 2);
		dot_new_operands.put("S2_storerinew_pci", 2);
		dot_new_operands.put("S2_storerinew_pcr", 2);
		dot_new_operands.put("S2_storerbnew_io", 1);
		dot_new_operands.put("S2_storerbnew_pi", 1);
		dot_new_operands.put("S4_storerbnew_ap", 1);
		dot_new_operands.put("S2_storerbnew_pr", 2);
		dot_new_operands.put("S4_storerbnew_ur", 1);
		dot_new_operands.put("S2_storerbnew_pbr", 2);
		dot_new_operands.put("S2_storerbnew_pci", 2);
		dot_new_operands.put("S2_storerbnew_pcr", 2);
		dot_new_operands.put("S2_storerhnew_io", 1);
		dot_new_operands.put("S2_storerhnew_pi", 1);
		dot_new_operands.put("S4_storerhnew_ap", 1);
		dot_new_operands.put("S2_storerhnew_pr", 2);
		dot_new_operands.put("S4_storerhnew_ur", 1);
		dot_new_operands.put("S2_storerhnew_pbr", 2);
		dot_new_operands.put("S2_storerhnew_pci", 2);
		dot_new_operands.put("S2_storerhnew_pcr", 2);
		dot_new_operands.put("S4_storerinew_rr", 2);
		dot_new_operands.put("S2_pstorerinewt_io", 2);
		dot_new_operands.put("S2_pstorerinewt_pi", 2);
		dot_new_operands.put("S2_pstorerinewf_io", 2);
		dot_new_operands.put("S2_pstorerinewf_pi", 2);
		dot_new_operands.put("S4_pstorerinewt_rr", 3);
		dot_new_operands.put("S4_pstorerinewf_rr", 3);
		dot_new_operands.put("S4_pstorerinewt_abs", 1);
		dot_new_operands.put("S4_pstorerinewf_abs", 1);
		dot_new_operands.put("S4_storerbnew_rr", 2);
		dot_new_operands.put("S2_pstorerbnewt_io", 2);
		dot_new_operands.put("S2_pstorerbnewt_pi", 2);
		dot_new_operands.put("S2_pstorerbnewf_io", 2);
		dot_new_operands.put("S2_pstorerbnewf_pi", 2);
		dot_new_operands.put("S4_pstorerbnewt_rr", 3);
		dot_new_operands.put("S4_pstorerbnewf_rr", 3);
		dot_new_operands.put("S4_pstorerbnewt_abs", 1);
		dot_new_operands.put("S4_pstorerbnewf_abs", 1);
		dot_new_operands.put("S4_storerhnew_rr", 2);
		dot_new_operands.put("S2_pstorerhnewt_io", 2);
		dot_new_operands.put("S2_pstorerhnewt_pi", 2);
		dot_new_operands.put("S2_pstorerhnewf_io", 2);
		dot_new_operands.put("S2_pstorerhnewf_pi", 2);
		dot_new_operands.put("S4_pstorerhnewt_rr", 3);
		dot_new_operands.put("S4_pstorerhnewf_rr", 3);
		dot_new_operands.put("S4_pstorerhnewt_abs", 1);
		dot_new_operands.put("S4_pstorerhnewf_abs", 1);
		dot_new_operands.put("S2_storerinewgp", 0);
		dot_new_operands.put("S2_storerbnewgp", 0);
		dot_new_operands.put("S2_storerhnewgp", 0);
	}

	Address addr;
	int parseBits;
	boolean endPacket;
	boolean isDuplex;
	boolean isImmext;
	HexagonInstructionInfo.DuplexEncoding duplex1;
	HexagonInstructionInfo.DuplexEncoding duplex2;
	Register newValueOperandRegister;

	HexagonInstructionInfo(Program program, Instruction instr, Address packetStartAddress)
			throws MemoryAccessException, UnknownInstructionException {
		this.addr = instr.getAddress();
		endPacket = false;
		isDuplex = false;

		isImmext = instr.getMnemonicString().equals("A4_ext");

		if (instr.getLength() != 4) {
			// See comment in reallyDisassembleInstruction().
			// We cleared subinsn, so all "instructions" should be 4
			// bytes. Duplex instructions will appear as a 4-byte opaque
			// DUPLEX temporary instruction.
			throw new UnknownInstructionException();
		}

		BigInteger value = BigInteger.valueOf(((instr.getByte(1) & 0xc0) >> 6) & 0b011);
		parseBits = value.intValue();
		if (parseBits == 0b00) {
			// This is an end of packet, and a duplex instruction
			endPacket = true;
			isDuplex = true;

			int iclass1 = ((instr.getByte(1) & 0x20) >> 5) & 0b001;
			int iclass2 = ((instr.getByte(3) & 0xe0) >> 5) & 0b111;
			int iclass = (iclass2 << 1) | iclass1;
			switch (iclass) {
			case 0:
				duplex1 = DuplexEncoding.L1;
				duplex2 = DuplexEncoding.L1;
				break;
			case 1:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.L1;
				break;
			case 2:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.L2;
				break;
			case 3:
				duplex1 = DuplexEncoding.A;
				duplex2 = DuplexEncoding.A;
				break;
			case 4:
				duplex1 = DuplexEncoding.L1;
				duplex2 = DuplexEncoding.A;
				break;
			case 5:
				duplex1 = DuplexEncoding.L2;
				duplex2 = DuplexEncoding.A;
				break;
			case 6:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.A;
				break;
			case 7:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.A;
				break;
			case 8:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.L1;
				break;
			case 9:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.L2;
				break;
			case 10:
				duplex1 = DuplexEncoding.S1;
				duplex2 = DuplexEncoding.S1;
				break;
			case 11:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.S1;
				break;
			case 12:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.L1;
				break;
			case 13:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.L2;
				break;
			case 14:
				duplex1 = DuplexEncoding.S2;
				duplex2 = DuplexEncoding.S2;
				break;
			default:
				assert false;
			}
		}
		if (parseBits == 0b11) {
			endPacket = true;
		}

		resolveNewValueOperand(program, instr, packetStartAddress);
	}

	Address getAddress() {
		return addr;
	}

	private BigInteger getNewValueOperand(Instruction instr) throws UnknownInstructionException {
		Integer idx = dot_new_operands.get(instr.getMnemonicString());
		if (idx != null) {
			Object[] obj = instr.getOpObjects(idx);
			assert obj.length == 1;
			Object obj2 = obj[0];
			if (!(obj2 instanceof Scalar)) {
				Msg.error(this, "New-value operand wasn't a scalar (" + instr + ")");
				throw new UnknownInstructionException("New-value operand wasn't an immediate as expected");
			}
			Scalar s = (Scalar) obj2;
			return s.getBigInteger();
		}
		return null;
	}

	private void resolveNewValueOperand(Program program, Instruction instr, Address packetStartAddress)
			throws UnknownInstructionException {
		newValueOperandRegister = null;

		// N.B. duplex sub-instructions still appear as one placeholder
		// DUPLEX 4-byte instruction.
		//
		// However, duplex sub-instructions do not have new-value operands
		// (not to be confused with dot-new predicates) so we can analyze
		// this here

		if (isDuplex) {
			return;
		}

		BigInteger idx = getNewValueOperand(instr);
		if (idx == null) {
			return;
		}

		if (idx.intValue() == 0) {
			throw new UnknownInstructionException("New-value operand value is 0");
		}

		if ((idx.intValue() & 0b1) != 0) {
			throw new UnknownInstructionException("First bit of new-value operand is not 0");
		}

		int idx2 = idx.intValue();
		idx2 = (idx2 >> 1) & 0b11;

		Address start = instr.getAddress();

		for (int i = 0; i < idx2; ++i) {
			start = start.subtract(4);

			if (start.compareTo(packetStartAddress) < 0) {
				throw new UnknownInstructionException(
						"Invalid packet has dot-new operand pointing before the beginning of the packet");
			}

			Instruction inst = program.getListing().getInstructionAt(start);
			if (inst == null) {
				throw new UnknownInstructionException();
			}

			if (inst.getLength() != 4) {
				// sanity check that the math we did above was kosher
				throw new UnknownInstructionException();
			}

			if (inst.getMnemonicString().equals("A4_ext")) {
				// 10.10 New-Value operands
				//
				// “ahead” is defined here as the instruction encoded at a lower
				// memory address than the consumer instruction, not counting
				// empty slots or constant extenders.
				start = start.subtract(4);
			}
		}

		Instruction inst = program.getListing().getInstructionAt(start);
		if (inst == null) {
			throw new UnknownInstructionException();
		}

		extractNewValueOperandRegister(inst);
	}

	private void extractNewValueOperandRegister(Instruction inst) throws UnknownInstructionException {
		Integer idx = dot_new_producers.get(inst.getMnemonicString());
		if (idx == null) {
			throw new UnknownInstructionException(
					"Instruction producer for new-value operand did not have suitable register");
		}

		Object[] obj = inst.getOpObjects(idx);
		assert obj.length == 1;
		Object obj2 = obj[0];
		if (!(obj2 instanceof Register)) {
			Msg.error(this, "New-value producer wasn't a register (" + inst + ")");
			throw new UnknownInstructionException("New-value producer wasn't a register as expected");
		}
		newValueOperandRegister = (Register) obj2;
	}

	enum DuplexEncoding {
		A, L1, L2, S1, S2;

		int getValue() {
			switch (this) {
			case A:
				return 1;
			case L1:
				return 2;
			case L2:
				return 3;
			case S1:
				return 4;
			case S2:
				return 5;
			}
			assert false;
			return -1;
		}
	}
}
