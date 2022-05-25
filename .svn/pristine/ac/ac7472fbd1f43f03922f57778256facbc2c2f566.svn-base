package wise.querygen.service;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.ListIterator;

import javax.crypto.spec.OAEPParameterSpec;

import wise.querygen.dto.*;
import wise.querysetting.dbms.*;

public class QuerySettingEx {

	private ArrayList<Relation> loDtBackRel = new ArrayList<Relation>();
	public String vbCrLf = "\r\n";
	
	public <T> ArrayList<T> Select(ArrayList<T> array,ArrayList<Condition> where) {
		try {
			ArrayList<T> returnArray = new ArrayList<T>();
			
			for (Condition condition : where) {

				// Object value = field.get(condition.getConditionColmn());
				Object resultObj = new Object();
				switch (condition.getCondition()) {
				case Equals:
					for (T tmp : array) {
						// Object clsInstance = tmp.getClass().newInstance();
						// Method method =
						// tmp.getClass().getDeclaredMethod("get" +
						// condition.getConditionColmn());
						// Object resultObj = method.invoke(clsInstance,new
						// Object[] {});
					
							for (Field field : tmp.getClass().getDeclaredFields()) {
								field.setAccessible(true);
								if (condition.getConditionColmn().equals(field.getName())) {
									resultObj = field.get(tmp);
									if(resultObj == null)
										resultObj = "";
								}
						}
						if (resultObj.toString().equals(
								condition.getConditionValue())) {
							returnArray.add(tmp);
						}
					}
					array = returnArray;
					returnArray = new ArrayList<T>();
					break;
				case NotEquals:
					for (T tmp : array) {
						// Object clsInstance = tmp.getClass().newInstance();
						// Method method =
						// tmp.getClass().getDeclaredMethod("get" +
						// condition.getConditionColmn());
						// Object resultObj = method.invoke(clsInstance,new
						// Object[] {});
					
							for (Field field : tmp.getClass().getDeclaredFields()) {
								field.setAccessible(true);
								if (condition.getConditionColmn().equals(field.getName())) {
									resultObj = field.get(tmp);
									if(resultObj == null)
										resultObj = "";
								}
						}
						if (!resultObj.toString().equals(
								condition.getConditionValue())) {
							returnArray.add(tmp);
						}
					}
					array = returnArray;
					returnArray = new ArrayList<T>();
					
					break;
				case GreaterOrEquals:
					break;
				case GreaterThan:
					break;
				case LessOrEquals:
					break;
				case LessThan:
					break;
				default:
					break;
				}

				// }
				// Object value=field.get(obj);
				// System.out.println(field.getName()+","+value);
				// }
			}

			return array;
		} catch (IllegalAccessException e) {
			e.getStackTrace();
			System.out.println(e.getMessage());
		}

		return null;
	}

	@SuppressWarnings("unchecked")
	public ArrayList<DimensionTbl> MeaGrpRelDimTbl(
			ArrayList<Measure> aDtMeaGrp, ArrayList<DsViewTbl> aDtDsViewTbl,
			ArrayList<Relation> aDtRel) {

		ArrayList<Relation> oDtBackRel = new ArrayList<Relation>();

		ArrayList<Relation> oRows = new ArrayList<Relation>();
		ArrayList<Measure> oExisitRows = new ArrayList<Measure>();

		ArrayList<DimensionTbl> oDtDimTbl = new ArrayList<DimensionTbl>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();

//		try {
			for (Measure oMeasure : aDtMeaGrp) {
				ArrayList<String> oJoinTblCollect = new ArrayList<String>();

				ListIterator<Relation> it = aDtRel.listIterator();

				while (it.hasNext()) {

				}

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("FK_TBL_NM");
				condition.setConditionValue(oMeasure.getTBL_NM());
				conArray.add(condition);

				oRows.addAll((Collection<? extends Relation>) Select(aDtRel,
						conArray));

				for (Relation oDrRel : oRows) {

					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDrRel.getPK_TBL_NM());
					conArray.add(condition);

					oExisitRows.addAll((Collection<? extends Measure>) Select(
							aDtMeaGrp, conArray));

					if (oExisitRows.size() == 0) {
						if (!oJoinTblCollect.contains(oDrRel.getPK_TBL_NM())) {
							oJoinTblCollect.add(oDrRel.getPK_TBL_NM());
						}
					}
				}

				for (String oT : oJoinTblCollect) {
					ArrayList<DimensionTbl> oTblRows = new ArrayList<DimensionTbl>();

					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oT);
					conArray.add(condition);

					if (Select(oDtDimTbl, conArray).size() == 0) {

						DimensionTbl oRow = new DimensionTbl();
						oRow.setPARENT_TBL_NM(oT);
						oRow.setTBL_NM(oT);

						// GetSnowFlakeBack(oDtBackRel, oDr("TBL_NM"), oT,
						// aDtRel);

						for (Relation oDrRel : oDtBackRel) {

							conArray = new ArrayList<Condition>();
							condition = new Condition();
							condition.setCondition(Comparison.Equals);
							condition.setConditionColmn("TBL_NM");
							condition.setConditionValue(oDrRel.getPK_TBL_NM());
							conArray.add(condition);

							if (Select(oDtDimTbl, conArray).size() == 0
									& !oJoinTblCollect.contains(oDrRel
											.getPK_TBL_NM())) {

								oRow.setPARENT_TBL_NM(oT);
								oRow.setTBL_NM(Select(aDtDsViewTbl, conArray)
										.get(0).getTBL_NM());

							}
						}
					}
				}
			}
//		} catch (Exception ex) {
//
//		}

		return oDtDimTbl;
	}

	public String TblAliasNm(String aDimUniNm) {
		String[] aData = aDimUniNm.split(".");
		String sAliasNm = "";

		sAliasNm = aDimUniNm.replace("[", "").replace("]", "");

		return sAliasNm;
	}

	public String GenTblAliasNm(ArrayList<Relation> aDtRtn, String aFkTblNm,
			String aPkTblNm, String aTblAliasNm, String aGrpYn) {
		String sReturn = "";
		String sNewTblAliasNm = aTblAliasNm;

		if (aDtRtn.size() > 0) {
			if (!aGrpYn.equalsIgnoreCase("Y")) {
				boolean bTure = true;
				int sIndex = 0;

				do {

					ArrayList<Relation> oRows = new ArrayList<Relation>();
					if (oRows.size() > 0) {
						sIndex += 1;
						sNewTblAliasNm = aTblAliasNm + Integer.toString(sIndex);
					} else
						bTure = true;

				} while (bTure);
			}
		}
		sReturn = sNewTblAliasNm;

		return sReturn;
	}

	@SuppressWarnings("unchecked")
	public void SnowRelChk(String aFkTblNm, String aFinishTbl,
			ArrayList<Relation> aDtRel, ArrayList<Relation> aDtBackRel) {
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();

		if (!aFkTblNm.equalsIgnoreCase(aFinishTbl)) {
			conArray = new ArrayList<Condition>();
			condition = new Condition();
			condition.setCondition(Comparison.Equals);
			condition.setConditionColmn("FK_TBL_NM");
			condition.setConditionValue(aFkTblNm);
			conArray.add(condition);

			ArrayList<Relation> oRows = (ArrayList<Relation>) Select(aDtRel,conArray);

			if (oRows.size() > 0) {
				outerloop: for (Relation oDr : oRows) {
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("CONST_NM");
					condition.setConditionValue(oDr.getCONST_NM());
					conArray.add(condition);

					int tmp = Select(aDtBackRel, conArray).size();
					if (tmp == 0) {
						Relation oRow = new Relation();

						oRow.setCONST_NM(oDr.getCONST_NM());
						oRow.setFK_TBL_NM(oDr.getFK_TBL_NM());
						oRow.setPK_TBL_NM(oDr.getPK_TBL_NM());

						loDtBackRel.add(oRow);

						SnowRelChk(oDr.getPK_TBL_NM(), aFinishTbl, aDtRel,
								loDtBackRel);
					} else {
						if (!oDr.getPK_TBL_NM().equalsIgnoreCase(
								oDr.getFK_TBL_NM()))
							SnowRelChk(oDr.getPK_TBL_NM(), aFinishTbl, aDtRel,
									loDtBackRel);
						else
							break outerloop;
					}
				}
			}
		}

	}

	public String CubeNonRelTbl(ArrayList<Hierarchy> aDtSelHieCopy,
								ArrayList<SelectCubeWhere> aDtWhereCopy,
								ArrayList<SelectCubeOrder> aDtOrderCopy,
								ArrayList<String> aJoinClauseColl,
								String aFromTblNm,
								ArrayList<String> aMeaGrpColl)
	{
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		ArrayList<String> oNotJoinTbl = new ArrayList<String>();
		ArrayList<String> oTblColl = new ArrayList<String>();
		ArrayList<Hierarchy> oRowSel = aDtSelHieCopy;
		ArrayList<SelectCubeWhere> oRowWhere = new ArrayList<SelectCubeWhere>();
		ArrayList<SelectCubeOrder> oRowOrder = new ArrayList<SelectCubeOrder>();
		String sNonJoinTbl = "";
		
		for(Hierarchy oDr : oRowSel)
		{
//			if(aFromTblNm != oDr.getTBL_NM())
			if(!aFromTblNm.equals(oDr.getTBL_NM()))
			{
				if(!aJoinClauseColl.contains(oDr.getTBL_NM()))
				{
					if(!oNotJoinTbl.contains(oDr.getTBL_NM()))
					{
						oNotJoinTbl.add(oDr.getTBL_NM());
						
						if(sNonJoinTbl.equals(""))
							sNonJoinTbl = oDr.getTBL_NM();
						else
							sNonJoinTbl = sNonJoinTbl + "," +oDr.getTBL_NM();
							
					}
				}
			}
			
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		conArray = new ArrayList<Condition>();
		condition = new Condition();
		condition.setCondition(Comparison.Equals);
		condition.setConditionColmn("TYPE");
		condition.setConditionValue("DIM");
		conArray.add(condition);
		
		oRowWhere = Select(aDtWhereCopy,conArray);
		
		for(SelectCubeWhere oDr : oRowWhere)
		{
//			if(aFromTblNm != oDr.getTBL_NM())
			if(!aFromTblNm.equals(oDr.getTBL_NM()))
			{
				if(!aJoinClauseColl.contains(oDr.getTBL_NM()))
				{
					if(!oNotJoinTbl.contains(oDr.getTBL_NM()))
					{
						oNotJoinTbl.add(oDr.getTBL_NM());
						
						if(sNonJoinTbl.equals(""))
							sNonJoinTbl = oDr.getTBL_NM();
						else
							sNonJoinTbl = sNonJoinTbl + "," +oDr.getTBL_NM();
							
					}
				}
			}
			
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		conArray = new ArrayList<Condition>();
		condition = new Condition();
		condition.setCondition(Comparison.Equals);
		condition.setConditionColmn("TYPE");
		condition.setConditionValue("DIM");
		conArray.add(condition);
		
		oRowOrder = Select(aDtOrderCopy,conArray);
		
		for(SelectCubeOrder oDr : oRowOrder)
		{
			if(aFromTblNm != oDr.getTBL_NM())
			{
				if(!aJoinClauseColl.contains(oDr.getTBL_NM()))
				{
					if(!oNotJoinTbl.contains(oDr.getTBL_NM()))
					{
						oNotJoinTbl.add(oDr.getTBL_NM());
						
						if(sNonJoinTbl.equals(""))
							sNonJoinTbl = oDr.getTBL_NM();
						else
							sNonJoinTbl = sNonJoinTbl + "," +oDr.getTBL_NM();
							
					}
				}
			}
			
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		if(aMeaGrpColl.size() == 0)
			if(oTblColl.size() == 1)
				return "";
			else
				return sNonJoinTbl;
		else
			return sNonJoinTbl;
	}
	
	@SuppressWarnings("unchecked")
	public ArrayList<Relation> CubeJoinSetting(ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea,
			ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder,
			ArrayList<Relation> aDtCubeRel, ArrayList<Relation> aDtDsViewRel,
			boolean aCubeYn) {
		ArrayList<Relation> oDtRtn = new ArrayList<Relation>();
		ArrayList<Hierarchy> oDtHie = new ArrayList<Hierarchy>();
		ArrayList<String> oMeaGrpColl = new ArrayList<String>();
		ArrayList<String> oDimColl = new ArrayList<String>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();

		for (SelectCubeMeasure oDr : aDtSelMea) {
			if (!oMeaGrpColl.contains(oDr.getMEA_GRP_UNI_NM()))
				oMeaGrpColl.add(oDr.getMEA_GRP_UNI_NM());

		}
		for (Hierarchy oDr : aDtSelHIe) {
			if (!oDimColl.contains(oDr.getDIM_UNI_NM()))
				oDimColl.add(oDr.getDIM_UNI_NM());

			Hierarchy oRow = new Hierarchy();
			oRow.setDIM_UNI_NM(oDr.getDIM_UNI_NM());
			oRow.setHIE_UNI_NM(oDr.getHIE_UNI_NM());
			oRow.setHIE_CAPTION(oDr.getHIE_CAPTION());
			oRow.setTBL_NM(oDr.getTBL_NM());
			oRow.setCOL_NM(oDr.getCOL_NM());
			oRow.setCOL_EXPRESS(oDr.getCOL_EXPRESS());

			oDtHie.add(oRow);
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("MEA")) {
				if (!oMeaGrpColl.contains(oDr.getPARENT_UNI_NM())) {
					oMeaGrpColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("DIM")) {
				if (!oDimColl.contains(oDr.getPARENT_UNI_NM())) {
					oDimColl.add(oDr.getPARENT_UNI_NM());
				}

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("HIE_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);

				ArrayList<Hierarchy> oExists = (ArrayList<Hierarchy>) Select(
						oDtHie, conArray);

				if (oExists.size() == 0) {
					Hierarchy oRow = new Hierarchy();
					oRow.setDIM_UNI_NM(oDr.getPARENT_UNI_NM());
					oRow.setHIE_UNI_NM(oDr.getUNI_NM());
					oRow.setHIE_CAPTION(oDr.getCAPTION());
					oRow.setTBL_NM(oDr.getTBL_NM());
					oRow.setCOL_EXPRESS(oDr.getCOL_EXPRESS());
					
					oDtHie.add(oRow);
				}

			}
		}

		/* PARENT_UNI_NM 항목이 없음 일단 주석처리 */
		/*
		 * for (SelectCubeOrder oDr : aDtOrder) { if
		 * (oDr.getTYPE().equals("MEA")) { if
		 * (!oMeaGrpColl.contains(oDr.getPARENT_UNI_NM())) {
		 * oMeaGrpColl.add(oDr.getPARENT_UNI_NM()); } } }
		 * 
		 * for (SelectCubeOrder oDr : aDtOrder) { if
		 * (oDr.getTYPE().equals("DIM")) { if
		 * (!oDimColl.contains(oDr.getPARENT_UNI_NM())) {
		 * oDimColl.add(oDr.getPARENT_UNI_NM()); }
		 * 
		 * ArrayList<Hierarchy> oExists = (ArrayList<Hierarchy>)
		 * Select(oDtHie,"HIE_UNI_NM = '" + oDr.getUNI_NM() + "'");
		 * 
		 * if(oExists.size() == 0) { Hierarchy oRow = new Hierarchy();
		 * oRow.setDIM_UNI_NM(oDr.getPARENT_UNI_NM());
		 * oRow.setHIE_UNI_NM(oDr.getUNI_NM());
		 * oRow.setHIE_CAPTION(oDr.getCAPTION());
		 * oRow.setTBL_NM(oDr.getTBL_NM());
		 * oRow.setCOL_EXPRESS(oDr.getCOL_EXPRESS()); }
		 * 
		 * } }
		 */

		ArrayList<Hierarchy> oDimRows = oDtHie;

		if (oMeaGrpColl.size() > 0) {
			for (String sMeaGrpNm : oMeaGrpColl) {
				for (String sDim : oDimColl) {
					loDtBackRel.clear();

					String sExceptTblNm = "";

					ArrayList<Relation> oRows = new ArrayList<Relation>();

					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("DIM_UNI_NM");
					condition.setConditionValue(sDim);
					conArray.add(condition);

					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("MEA_GRP_UNI_NM");
					condition.setConditionValue(sMeaGrpNm);
					conArray.add(condition);

					oRows = (ArrayList<Relation>) Select(aDtCubeRel, conArray);

					if (oRows.size() > 0) {
						for (Relation oDr : oRows) {
							conArray = new ArrayList<Condition>();
							condition = new Condition();
							condition.setCondition(Comparison.Equals);
							condition.setConditionColmn("CONST_NM");
							condition.setConditionValue(oDr.getCONST_NM());
							conArray.add(condition);

							if (Select(loDtBackRel, conArray).size() == 0) {
								Relation oRow = new Relation();
								oRow.setCONST_NM(oDr.getCONST_NM());
								oRow.setFK_TBL_NM(oDr.getFK_TBL_NM());
								oRow.setPK_TBL_NM(oDr.getPK_TBL_NM());
								loDtBackRel.add(oRow);
							}

							sExceptTblNm = oDr.getPK_TBL_NM();
						}
					}

					ArrayList<String> oDimTblColl = new ArrayList<String>();

					oRows.clear();

					ArrayList<Hierarchy> oHieRows = new ArrayList<Hierarchy>();

					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("DIM_UNI_NM");
					condition.setConditionValue(sDim);
					conArray.add(condition);

					oHieRows = (ArrayList<Hierarchy>) Select(oDtHie, conArray);

					for (Hierarchy oDr : oHieRows) {
						if (!oDr.getTBL_NM().equalsIgnoreCase(sExceptTblNm)) {
							if (!oDimTblColl.contains(oDr.getTBL_NM())) {
								oDimTblColl.add(oDr.getTBL_NM());
							}
						}
					}
//sssssss
					if (oDimTblColl.size() == 0) {
						for (Relation oDr : loDtBackRel) {
							boolean sCubeRelYn = true;

							ArrayList<Relation> oTmpRelRows = new ArrayList<Relation>();

							conArray = new ArrayList<Condition>();
							condition = new Condition();
							condition.setCondition(Comparison.Equals);
							condition.setConditionColmn("CONST_NM");
							condition.setConditionValue(oDr.getCONST_NM());
							conArray.add(condition);

							oTmpRelRows = (ArrayList<Relation>) Select(
									aDtCubeRel, conArray);

							if (oTmpRelRows.size() == 0) {
								oTmpRelRows = Select(aDtDsViewRel, conArray);
								sCubeRelYn = false;
							}

							for (Relation oDrRel : oTmpRelRows) {
								ArrayList<Relation> oExistsRows = new ArrayList<Relation>();

								conArray = new ArrayList<Condition>();
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("CONST_NM");
								condition.setConditionValue(oDrRel
										.getCONST_NM());
								conArray.add(condition);

								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("FK_TBL_NM");
								condition.setConditionValue(oDrRel
										.getFK_TBL_NM());
								conArray.add(condition);

								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("FK_COL_NM");
								condition.setConditionValue(oDrRel
										.getFK_COL_NM());
								conArray.add(condition);

								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("PK_TBL_NM");
								condition.setConditionValue(oDrRel
										.getPK_TBL_NM());
								conArray.add(condition);

								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("PK_COL_NM");
								condition.setConditionValue(oDrRel
										.getPK_COL_NM());
								conArray.add(condition);
								
								/*dogfoot shlim 20210430*/
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("FK_EXPRESS");
								condition.setConditionValue(oDrRel
										.getFK_EXPRESS());
								conArray.add(condition);
								
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("PK_EXPRESS");
								condition.setConditionValue(oDrRel
										.getPK_EXPRESS());
								conArray.add(condition);

								oExistsRows = (ArrayList<Relation>) Select(
										oDtRtn, conArray);

								if (oExistsRows.size() == 0) {
									String sAliasTblNm = "";
									String sGrpYn = "";
									String sDimUniNm = "";
									String sJoinType = "INNER JOIN";

									if (oTmpRelRows.size() > 1)
										sGrpYn = "Y";
									else
										sGrpYn = "N";

//									try {
										if (sCubeRelYn) {
											sDimUniNm = oDrRel.getDIM_UNI_NM();
											sJoinType = oDrRel.getJOIN_TYPE();
										} else {
											if (aCubeYn)
												sDimUniNm = "["
														+ oDrRel.getPK_TBL_NM()
														+ "]";
											else
												sDimUniNm = oDrRel
														.getPK_TBL_NM();
										}
										sAliasTblNm = TblAliasNm(sDimUniNm);

//									} catch (Exception e) {
//										System.out.println(e.getMessage());
//										sAliasTblNm = "";
//									}

									Relation oRow = new Relation();

									oRow.setDIM_UNI_NM(oDrRel.getDIM_UNI_NM());
									oRow.setCONST_NM(oDrRel.getCONST_NM());
									oRow.setFK_TBL_NM(oDrRel.getFK_TBL_NM());
									oRow.setFK_COL_NM(oDrRel.getFK_COL_NM());
									oRow.setPK_TBL_NM(oDrRel.getPK_TBL_NM());
									oRow.setPK_COL_NM(oDrRel.getPK_COL_NM());
									/*dogfoot shlim 20210430*/
									oRow.setFK_EXPRESS(oDrRel.getFK_EXPRESS());
									oRow.setPK_EXPRESS(oDrRel.getPK_EXPRESS());
									oRow.setPK_TBL_ALIAS_NM(sAliasTblNm);
									oRow.setPK_TBL_GRP(sExceptTblNm);
									oRow.setPK_TBL_GRP_YN(sGrpYn);
									oRow.setJOIN_TYPE(sJoinType);
									oRow.setEXPRESSION(oDrRel.getEXPRESSION());
									oDtRtn.add(oRow);
								}
							}
						}
					} else {
						for (String oT : oDimTblColl) {
							SnowRelChk(sExceptTblNm, oT, aDtDsViewRel,
									loDtBackRel);

							boolean bTrue = false;
							ArrayList<String> oConstColl = new ArrayList<String>();

							if (loDtBackRel.size() > 0) {
								String sPkTblNm = oT;

								do {
									ArrayList<Relation> oTmpRows = new ArrayList<Relation>();

									conArray = new ArrayList<Condition>();
									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("PK_TBL_NM");
									condition.setConditionValue(sPkTblNm);
									conArray.add(condition);

									oTmpRows = (ArrayList<Relation>) Select(
											loDtBackRel, conArray);

									if (oTmpRows.size() == 0)
										bTrue = true;
									else {
										for (Relation oDrBack : oTmpRows) {
											if (!oConstColl.contains(oDrBack
													.getCONST_NM()))
												oConstColl.add(oDrBack
														.getCONST_NM());

											sPkTblNm = oDrBack.getFK_TBL_NM();
										}
									}

								} while (!bTrue);

								for (int ii = oConstColl.size() - 1; ii >= 0; ii--) {
									boolean sCubeRelYn = true;

									ArrayList<Relation> oTmpRelRows = new ArrayList<Relation>();

									conArray = new ArrayList<Condition>();
									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("CONST_NM");
									condition.setConditionValue(oConstColl
											.get(ii));
									conArray.add(condition);

									oTmpRelRows = (ArrayList<Relation>) Select(
											aDtCubeRel, conArray);

									if (oTmpRelRows.size() == 0) {
										oTmpRelRows = (ArrayList<Relation>) Select(
												aDtDsViewRel, conArray);
										sCubeRelYn = false;
									}

									for (Relation oDrRel : oTmpRelRows) {
										ArrayList<Relation> oExistsRows = new ArrayList<Relation>();

										conArray = new ArrayList<Condition>();
										condition = new Condition();
										condition
												.setCondition(Comparison.Equals);
										condition.setConditionColmn("CONST_NM");
										condition.setConditionValue(oDrRel
												.getCONST_NM());
										conArray.add(condition);

										condition = new Condition();
										condition
												.setCondition(Comparison.Equals);
										condition
												.setConditionColmn("FK_TBL_NM");
										condition.setConditionValue(oDrRel
												.getFK_TBL_NM());
										conArray.add(condition);

										condition = new Condition();
										condition
												.setCondition(Comparison.Equals);
										condition
												.setConditionColmn("FK_COL_NM");
										condition.setConditionValue(oDrRel
												.getFK_COL_NM());
										conArray.add(condition);

										condition = new Condition();
										condition
												.setCondition(Comparison.Equals);
										condition
												.setConditionColmn("PK_TBL_NM");
										condition.setConditionValue(oDrRel
												.getPK_TBL_NM());
										conArray.add(condition);

										condition = new Condition();
										condition
												.setCondition(Comparison.Equals);
										condition
												.setConditionColmn("PK_COL_NM");
										condition.setConditionValue(oDrRel
												.getPK_COL_NM());
										conArray.add(condition);

										oExistsRows = (ArrayList<Relation>) Select(
												oDtRtn, conArray);

										if (oExistsRows.size() == 0) {
											String sAliasTblNm = "";
											String sGrpYn = "";
											String sDimUniNm = "";
											String sJoinType = "INNER JOIN";

											if (oTmpRelRows.size() > 1)
												sGrpYn = "Y";
											else
												sGrpYn = "N";

//											try {
												if (sCubeRelYn) {
													sDimUniNm = oDrRel
															.getDIM_UNI_NM();
													sJoinType = oDrRel
															.getJOIN_TYPE();
												} else {
													if (aCubeYn)
														sDimUniNm = "[" + oDrRel.getPK_TBL_NM() + "]";
													else
														sDimUniNm = oDrRel
																.getPK_TBL_NM();
												}
												sAliasTblNm = TblAliasNm(sDimUniNm);

//											} catch (Exception e) {
//												System.out.println(e
//														.getMessage());
//												sAliasTblNm = "";
//											}

											Relation oRow = new Relation();

											oRow.setDIM_UNI_NM(sDimUniNm);
											oRow.setCONST_NM(oDrRel.getCONST_NM());
											oRow.setFK_TBL_NM(oDrRel.getFK_TBL_NM());
											oRow.setFK_COL_NM(oDrRel.getFK_COL_NM());
											oRow.setPK_TBL_NM(oDrRel.getPK_TBL_NM());
											oRow.setPK_COL_NM(oDrRel.getPK_COL_NM());
											oRow.setPK_TBL_ALIAS_NM(sAliasTblNm);
											oRow.setPK_TBL_GRP(sExceptTblNm);
											oRow.setPK_TBL_GRP_YN(sGrpYn);
											oRow.setJOIN_TYPE(sJoinType);
											
											oDtRtn.add(oRow);
										}
									}
								}
							}

						}
					}
				}
			}
		} //Measure end
		else {
			ArrayList<Hierarchy> oDt = new ArrayList<Hierarchy>();
			ArrayList<Hierarchy> oRows = new ArrayList<Hierarchy>();
			if (oDimRows.size() > 1) {
				oDt = oDimRows;

				for (Hierarchy oDrDim : oDimRows) {

					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.NotEquals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDrDim.getTBL_NM());
					conArray.add(condition);

					oRows = (ArrayList<Hierarchy>) Select(oDt, conArray);

					for (Hierarchy oDr : oRows) {
						loDtBackRel.clear();
						
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("DIM_UNI_NM");
						condition.setConditionValue(oDr.getDIM_UNI_NM());
						conArray.add(condition);
						
						ArrayList<Relation> oRows1 = Select(aDtCubeRel,conArray);
						
						if(oRows1.size() > 0)
						{
							for (Relation oDr1 : oRows1) {
								
								conArray = new ArrayList<Condition>();
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("CONST_NM");
								condition.setConditionValue(oDr1.getCONST_NM());
								conArray.add(condition);
								
								if(Select(loDtBackRel,conArray).size() == 0)
								{
									Relation oTmpRel = new Relation();
									
									oTmpRel.setCONST_NM(oDr1.getCONST_NM());
									oTmpRel.setFK_TBL_NM(oDr1.getCONST_NM());
									oTmpRel.setPK_TBL_NM(oDr1.getPK_TBL_NM());
									
									loDtBackRel.add(oTmpRel);
								}
							}
						}
						
						SnowRelChk(oDrDim.getTBL_NM(), oDr.getTBL_NM(),
								aDtDsViewRel, loDtBackRel);

						boolean bTrue = false;
						ArrayList<String> oConstColl = new ArrayList<String>();

						if (loDtBackRel.size() > 0) {
							String sPkTblNm = oDr.getTBL_NM();

							do {
								ArrayList<Relation> oTmpRows = new ArrayList<Relation>();

								conArray = new ArrayList<Condition>();
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("PK_TBL_NM");
								condition.setConditionValue(sPkTblNm);
								conArray.add(condition);

								oTmpRows = (ArrayList<Relation>) Select(
										loDtBackRel, conArray);

								if (oTmpRows.size() == 0)
									bTrue = true;
								else {
									for (Relation oDrBack : oTmpRows) {
										if (!oConstColl.contains(oDrBack
												.getCONST_NM()))
											oConstColl.add(oDrBack
													.getCONST_NM());

										sPkTblNm = oDrBack.getFK_TBL_NM();
									}
								}

							} while (bTrue);
							
							for (int ii = oConstColl.size() - 1; ii >= 0; ii--) {

								ArrayList<Relation> oTmpRelRows = new ArrayList<Relation>();

								conArray = new ArrayList<Condition>();
								condition = new Condition();
								condition.setCondition(Comparison.Equals);
								condition.setConditionColmn("CONST_NM");
								condition.setConditionValue(oConstColl.get(ii));
								conArray.add(condition);

								oTmpRelRows = (ArrayList<Relation>) Select(
										aDtDsViewRel, conArray);

								for (Relation oDrRel : oTmpRelRows) {
									ArrayList<Relation> oExistsRows = new ArrayList<Relation>();

									conArray = new ArrayList<Condition>();
									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("CONST_NM");
									condition.setConditionValue(oDrRel
											.getCONST_NM());
									conArray.add(condition);

									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("FK_TBL_NM");
									condition.setConditionValue(oDrRel
											.getFK_TBL_NM());
									conArray.add(condition);

									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("FK_COL_NM");
									condition.setConditionValue(oDrRel
											.getFK_COL_NM());
									conArray.add(condition);

									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("PK_TBL_NM");
									condition.setConditionValue(oDrRel
											.getPK_TBL_NM());
									conArray.add(condition);

									condition = new Condition();
									condition.setCondition(Comparison.Equals);
									condition.setConditionColmn("PK_COL_NM");
									condition.setConditionValue(oDrRel
											.getPK_COL_NM());
									conArray.add(condition);

									oExistsRows = (ArrayList<Relation>) Select(
											oDtRtn, conArray);

									if (oExistsRows.size() == 0) {
										String sAliasTblNm = "";
										String sGrpYn = "";
										String sDimUniNm = oDrRel
												.getFK_TBL_NM();
										String sJoinType = "INNER JOIN";

										if (oTmpRelRows.size() > 1)
											sGrpYn = "Y";
										else
											sGrpYn = "N";

										sAliasTblNm = TblAliasNm(sDimUniNm);

										Relation oRow = new Relation();

										oRow.setDIM_UNI_NM(oDrRel.getDIM_UNI_NM());
										oRow.setCONST_NM(oDrRel.getCONST_NM());
										oRow.setFK_TBL_NM(oDrRel.getFK_TBL_NM());
										oRow.setFK_COL_NM(oDrRel.getFK_COL_NM());
										oRow.setPK_TBL_NM(oDrRel.getPK_TBL_NM());
										oRow.setPK_COL_NM(oDrRel.getPK_COL_NM());
										oRow.setPK_TBL_ALIAS_NM(sAliasTblNm);
										oRow.setPK_TBL_GRP(sPkTblNm);
										oRow.setPK_TBL_GRP_YN(sGrpYn);
										oRow.setJOIN_TYPE(sJoinType);
										
										oDtRtn.add(oRow);
									}
								}
							}
						}
					}
				}
			}
		}
		return oDtRtn;
	}
	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	public String ColumnAliasNm(String aDbmsType,String aColumnNm)
	{
		String sAliasNm = "";
		
		if (aDbmsType.equalsIgnoreCase("MS-SQL"))
		{
			MSSQLSetting oSetting = new MSSQLSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("ORACLE") || aDbmsType.equalsIgnoreCase("ALTIBASE"))
		{
			OracleSetting oSetting = new OracleSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("DB2BLU"))
		{
			DB2BLUSetting oSetting = new DB2BLUSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("DB2"))
		{
			DB2BLUSetting oSetting = new DB2BLUSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("NETEZZA"))
		{
			NETEZZASetting oSetting = new NETEZZASetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("TIBERO") || aDbmsType.equalsIgnoreCase("TBIN"))
		{
			TiberoSetting oSetting = new TiberoSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("SAPIQ"))
		{
			SybaseSetting oSetting = new SybaseSetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		if (aDbmsType.equalsIgnoreCase("IMPALA") || aDbmsType.equalsIgnoreCase("MARIA") || aDbmsType.equalsIgnoreCase("MYSQL"))
		{
			IMPALASetting oSetting = new IMPALASetting();
			sAliasNm = oSetting.ColumnAliasNm(aColumnNm);
		}
		return sAliasNm;
	}
	
	public ArrayList<String> CubeSelClauseForRenameTable(String aDBMSType,
											ArrayList<SelectCube> aDtSel,
											ArrayList<Hierarchy> aDtSelHie,
											ArrayList<SelectCubeMeasure> aDtSelMea,
											String aMeaGrpUniNm,
											ArrayList<TblAlias> aDtTblAlias)
	{
		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(SelectCube oDr : aDtSel)
		{
			if("MEA".equalsIgnoreCase(oDr.getTYPE()))
			{
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);
				
				ArrayList<SelectCubeMeasure> oRows = Select(aDtSelMea,conArray);
				
				String oColCaption = ColumnAliasNm(aDBMSType, oDr.getCAPTION());
				if(oRows.size() > 0)
				{
					if(oRows.get(0).getMEA_GRP_UNI_NM().equalsIgnoreCase(aMeaGrpUniNm))
					{
						String sColExpress = oRows.get(0).getCOL_EXPRESS();
						
						if(sColExpress != null && !sColExpress.equals(""))
						{
							if(oRows.get(0).getMEA_AGG().equalsIgnoreCase("Distinct Count"))
								oSelClauseColl.add("Count" + "(Distinct " + sColExpress + ")" + " AS " + oColCaption);
							else if(oRows.get(0).getMEA_AGG().equalsIgnoreCase(""))
								oSelClauseColl.add("(" + sColExpress + ")" + " AS " + oColCaption);
							else
								oSelClauseColl.add(oRows.get(0).getMEA_AGG() + "(" + sColExpress + ")" + " AS " + oColCaption);
						}
						else
						{
							String oTblNm = "A";
							String oColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getMEA_COL_NM());
							
//							if(oRows.get(0).getMEA_AGG().equalsIgnoreCase("Distinct Count"))
//								oSelClauseColl.add("Count" + "(Distinct " + oTblNm + "." + oColNm + ")" + " AS " + oColCaption);
//							else if(oRows.get(0).getMEA_AGG().equalsIgnoreCase(""))
								oSelClauseColl.add(oTblNm + "." + oColCaption);
//							else
//								oSelClauseColl.add(oRows.get(0).getMEA_AGG() + "(" + oTblNm + "." + oColNm + ")" + " AS " + oColCaption);
						}
					}
					else
					{
						oSelClauseColl.add("NULL AS " + oColCaption);
					}
				}
				
			}
			else if("DIM".equalsIgnoreCase(oDr.getTYPE()))
			{
				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("HIE_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);
				
				ArrayList<Hierarchy> oRows = Select(aDtSelHie,conArray);
				
				if(oRows.size() > 0)
				{
					String sColExpress = oRows.get(0).getCOL_EXPRESS();
					String sTblNm = "A";
					String sColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getCOL_NM());
					String sColCaption = ColumnAliasNm(aDBMSType, oDr.getCAPTION());
					
					String sKeyValue = "";
					String sKeyValue_K = "";
					String sAliasTblNm = "";
					
					ArrayList<TblAlias> oAliasRows = new ArrayList<TblAlias>();
					
					if(aDtTblAlias.size() > 0 || !aDtTblAlias.equals(null))
					{
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue(oRows.get(0).getDIM_UNI_NM());
						conArray.add(condition);
						
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("TBL_NM");
						condition.setConditionValue(oRows.get(0).getTBL_NM());
						conArray.add(condition);
						
						oAliasRows = Select(aDtTblAlias,conArray);
						
						sAliasTblNm = oRows.get(0).getDIM_UNI_NM();
						
						
					}
/*
					if(oRows.size() > 1)
					{
						if(oAliasRows.size() > 0)
							sKeyValue_K = oAliasRows.get(0).getALIAS_TBL_NM() + "." +  oRows.get(1).getCOL_NM() + " AS " + ColumnAliasNm(aDBMSType, oDr.getCAPTION()+ "_K");
						else
							sKeyValue_K = sTblNm + "." + oRows.get(1).getCOL_NM() + " AS " + ColumnAliasNm(aDBMSType, oRows.get(0).getHIE_CAPTION());
					}
*/					
					if(sColExpress != null && !sColExpress.equals(""))
						sKeyValue = "(" + sColExpress + ")" + ColumnAliasNm(aDBMSType, oRows.get(0).getHIE_CAPTION());
					else
					{
						sKeyValue = sTblNm + "." + ColumnAliasNm(aDBMSType, oDr.getCAPTION());
						
						if(oAliasRows.size() > 0)
							for(int i=0;i<oAliasRows.size();i++) {
								if(sTblNm.equalsIgnoreCase(oAliasRows.get(i).getTBL_NM()) && oAliasRows.get(i).getUNI_NM().equalsIgnoreCase(sAliasTblNm)) {
									sKeyValue = oAliasRows.get(i).getALIAS_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCAPTION());
									break;
								}
							}
							
								
					}
					
					oSelClauseColl.add(sKeyValue);
					
					if(sKeyValue_K != "")
						oSelClauseColl.add(sKeyValue_K);
				}
			}
		}
		
		return oSelClauseColl;
		
	}

	public ArrayList<String> CubeSelClause(String aDBMSType, ArrayList<SelectCube> aDtSel,
			ArrayList<Hierarchy> aDtSelHie, ArrayList<SelectCubeMeasure> aDtSelMea, String aMeaGrpUniNm,
			ArrayList<TblAlias> aDtTblAlias) {
		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();

		for (SelectCube oDr : aDtSel) {
			if ("MEA".equalsIgnoreCase(oDr.getTYPE())) {
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);

				ArrayList<SelectCubeMeasure> oRows = Select(aDtSelMea, conArray);

				String oColCaption = ColumnAliasNm(aDBMSType, oDr.getCAPTION());
				if (oRows.size() > 0) {
					if (oRows.get(0).getMEA_GRP_UNI_NM().equalsIgnoreCase(aMeaGrpUniNm)) {
						String sColExpress = oRows.get(0).getCOL_EXPRESS();
						/* 개발 cshan 1211
						 *  MEA_AGG에 공백이 포함되어 trim() 옵션 사용
						 *  */
						if (sColExpress != null && !sColExpress.equals("")) {
							if (oRows.get(0).getMEA_AGG().trim().equalsIgnoreCase("Distinct Count"))
								oSelClauseColl.add("Count" + "(Distinct " + sColExpress + ")" + " AS " + oColCaption);
							else if (oRows.get(0).getMEA_AGG().equalsIgnoreCase(""))
								oSelClauseColl.add("(" + sColExpress + ")" + " AS " + oColCaption);
							else {
								oSelClauseColl.add(
										oRows.get(0).getMEA_AGG() + "(" + sColExpress + ")" + " AS " + oColCaption);
							}
							//20210122 AJKIM 계산된 컬럼 추가 DOGFOOT
						} else if(oDr.getDATA_TYPE().equals("cal") || oDr.getDATA_TYPE().equals("grp")) {
							String oTblNm = oRows.get(0).getMEA_TBL_NM();
							String oColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getMEA_COL_NM());
							oSelClauseColl.add(oRows.get(0).getMEA_AGG() + "("+ oColNm.replaceAll("\"", "") + ")"
										+ " AS " + oColCaption);
						}
						else {
							String oTblNm = oRows.get(0).getMEA_TBL_NM();
							String oColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getMEA_COL_NM());
							/* DOGFOOT ktkang 주제영역 집계함수 부분 에러 수정 시작  20200225 */
							if (oRows.get(0).getMEA_AGG() != null && oRows.get(0).getMEA_AGG().trim().equalsIgnoreCase("Distinct Count"))
								oSelClauseColl.add(
										"Count" + "(Distinct " + oTblNm + "." + oColNm + ")" + " AS " + oColCaption);
							else if (oRows.get(0).getMEA_AGG() != null && oRows.get(0).getMEA_AGG().equalsIgnoreCase(""))
								oSelClauseColl.add(oTblNm + "." + oColNm + " AS " + oColCaption);
							else if(oRows.get(0).getMEA_AGG() != null)
							/* DOGFOOT ktkang 주제영역 집계함수 부분 에러 수정 끝  20200225 */
								oSelClauseColl.add(oRows.get(0).getMEA_AGG() + "(" + oTblNm + "." + oColNm + ")"
										+ " AS " + oColCaption);
						}
					} else {
						oSelClauseColl.add("NULL AS " + oColCaption);
					}
				}

			} else if ("DIM".equalsIgnoreCase(oDr.getTYPE())) {
				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("HIE_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);

				ArrayList<Hierarchy> oRows = Select(aDtSelHie, conArray);

				if (oRows.size() > 0) {
					String sColExpress = oRows.get(0).getCOL_EXPRESS();
					String sTblNm = oRows.get(0).getTBL_NM();
					String sColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getCOL_NM());
					String sColCaption = ColumnAliasNm(aDBMSType, oDr.getCAPTION());

					String sKeyValue = "";
					String sKeyValue_K = "";
					String sAliasTblNm = "";

					ArrayList<TblAlias> oAliasRows = new ArrayList<TblAlias>();

					if (aDtTblAlias.size() > 0 || !aDtTblAlias.equals(null)) {
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue(oRows.get(0).getDIM_UNI_NM());
						conArray.add(condition);

						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("TBL_NM");
						condition.setConditionValue(oRows.get(0).getTBL_NM());
						conArray.add(condition);

						oAliasRows = Select(aDtTblAlias, conArray);

						sAliasTblNm = oRows.get(0).getDIM_UNI_NM();

					}
					/*
					 * if(oRows.size() > 1) { if(oAliasRows.size() > 0) sKeyValue_K =
					 * oAliasRows.get(0).getALIAS_TBL_NM() + "." + oRows.get(1).getCOL_NM() + " AS "
					 * + ColumnAliasNm(aDBMSType, oDr.getCAPTION()+ "_K"); else sKeyValue_K = sTblNm
					 * + "." + oRows.get(1).getCOL_NM() + " AS " + ColumnAliasNm(aDBMSType,
					 * oRows.get(0).getHIE_CAPTION()); }
					 */
					if (sColExpress != null && !sColExpress.equals(""))
						sKeyValue = "(" + sColExpress + ")" + " AS "
								+ ColumnAliasNm(aDBMSType, oRows.get(0).getHIE_CAPTION());
					else {
						sKeyValue = sTblNm + "." + sColNm + " AS " + ColumnAliasNm(aDBMSType, oDr.getCAPTION());

						if (oAliasRows.size() > 0)
							for (int i = 0; i < oAliasRows.size(); i++) {
								if (sTblNm.equalsIgnoreCase(oAliasRows.get(i).getTBL_NM())
										&& oAliasRows.get(i).getUNI_NM().equalsIgnoreCase(sAliasTblNm)) {
									sKeyValue = oAliasRows.get(i).getALIAS_TBL_NM() + "." + sColNm + " AS "
											+ ColumnAliasNm(aDBMSType, oDr.getCAPTION());
									break;
								}
							}

					}

					oSelClauseColl.add(sKeyValue);

					if (sKeyValue_K != "")
						oSelClauseColl.add(sKeyValue_K);
				}
			}
		}

		return oSelClauseColl;

	}
	
	public String ConvertDataType(String aDataType)
	{
		String sReturn = "VARCHAR";
		
		if(aDataType.equalsIgnoreCase("INT") 
				|| aDataType.equalsIgnoreCase("TINYINT") 
				|| aDataType.equalsIgnoreCase("DECIMAL") 
				|| aDataType.equalsIgnoreCase("FLOAT") 
				|| aDataType.equalsIgnoreCase("MONEY") 
				|| aDataType.equalsIgnoreCase("REAL") 
				|| aDataType.equalsIgnoreCase("SMALLINT")
				|| aDataType.equalsIgnoreCase("SMALLMONEY")
				|| aDataType.equalsIgnoreCase("TINYINT")
				|| aDataType.equalsIgnoreCase("XML")
				|| aDataType.equalsIgnoreCase("NUMBER")
				|| aDataType.equalsIgnoreCase("NUMERIC")
				|| aDataType.equalsIgnoreCase("VARGRAPHIC")
				|| aDataType.equalsIgnoreCase("DOUBLE"))
			sReturn = "NUMBER";
		
		if(aDataType.equalsIgnoreCase("NVARCHAR") 
				|| aDataType.equalsIgnoreCase("VARCHAR") 
				|| aDataType.equalsIgnoreCase("NCHAR") 
				|| aDataType.equalsIgnoreCase("CHAR") 
				|| aDataType.equalsIgnoreCase("NTEXT") 
				|| aDataType.equalsIgnoreCase("TEXT") )
			sReturn = "VARCHAR";
			
		if(aDataType.equalsIgnoreCase("DATE") 
				|| aDataType.equalsIgnoreCase("DATETIME") 
				|| aDataType.equalsIgnoreCase("DATETIMEOFFSET") 
				|| aDataType.equalsIgnoreCase("SMALLDATETIME") 
				|| aDataType.equalsIgnoreCase("TIME") 
				|| aDataType.equalsIgnoreCase("TIMESTAMP") )
			sReturn = "DateTime";
		
		if(aDataType.equalsIgnoreCase("BIT"))
			sReturn = "Boolean";
			
		return sReturn;
	}
	
	public String CheckValue(String aValue)
	{
		return aValue.replace(vbCrLf, "");
	}
	/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
	public ArrayList<String> CubeGroupByByClause(String aDBMSType,
														ArrayList<Hierarchy> aDtSelHie,
														ArrayList<TblAlias> aDtTblAlias, ArrayList<SelectCube> aDtSel, ArrayList<SelectCubeMeasure> aDtSelMea)
	{
		ArrayList<String> oGroupByColl = new ArrayList<String>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(Hierarchy oDr : aDtSelHie)
		{
			String sKeyValue = "";
			String sColExpress= oDr.getCOL_EXPRESS();
			
			if (sColExpress != null && !sColExpress.equals(""))
				sKeyValue = "(" + sColExpress + ")";
			else
			{
				String sTblNm = oDr.getTBL_NM();
				String sColNm = ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
				String sAliasTblNm = oDr.getDIM_UNI_NM();
				if(aDtTblAlias.size() > 0)
				{
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("UNI_NM");
					condition.setConditionValue(oDr.getDIM_UNI_NM());
					conArray.add(condition);
					
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDr.getTBL_NM());
					conArray.add(condition);
					
					ArrayList<TblAlias> oAliasRows = Select(aDtTblAlias,conArray);
					
					if (oAliasRows.size() > 0)
						for(int i=0;i<oAliasRows.size();i++) {
							if(sTblNm.equalsIgnoreCase(oAliasRows.get(i).getTBL_NM()) && oAliasRows.get(i).getUNI_NM().equalsIgnoreCase(sAliasTblNm)) {
								sTblNm = oAliasRows.get(i).getALIAS_TBL_NM();
								break;
							}
						}
						
				}
				
				sKeyValue = sTblNm + "." + sColNm;
			}
			
			oGroupByColl.add(sKeyValue);
		}
		/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
		for (SelectCube oDr : aDtSel) {
			if ("MEA".equalsIgnoreCase(oDr.getTYPE())) {
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_UNI_NM");
				condition.setConditionValue(oDr.getUNI_NM());
				conArray.add(condition);

				ArrayList<SelectCubeMeasure> oRows = Select(aDtSelMea, conArray);

				String oColCaption = ColumnAliasNm(aDBMSType, oDr.getCAPTION());
				if (oRows.size() > 0) {
					
					String sColExpress = oRows.get(0).getCOL_EXPRESS();
					/* 개발 cshan 1211
					 *  MEA_AGG에 공백이 포함되어 trim() 옵션 사용
					 *  */
					if (sColExpress != null && !sColExpress.equals("")) {
//						if (oRows.get(0).getMEA_AGG().trim().equalsIgnoreCase("Distinct Count"))
//							oGroupByColl.add("Count" + "(Distinct " + sColExpress + ")" + " AS " + oColCaption);
//						else 
							if (oRows.get(0).getMEA_AGG() == null ||oRows.get(0).getMEA_AGG().equalsIgnoreCase(""))
							oGroupByColl.add("(" + sColExpress + ")" + " AS " + oColCaption);
						
					} else {
						String oTblNm = oRows.get(0).getMEA_TBL_NM();
						String oColNm = ColumnAliasNm(aDBMSType, oRows.get(0).getMEA_COL_NM());
						/* DOGFOOT 사용자정의컬럼 추가 시 group by 오류 수정 shlim 2020125 */
						 if (oRows.get(0).getMEA_AGG() != null && oRows.get(0).getMEA_AGG().trim().equalsIgnoreCase("")) {
							 if(oColNm.indexOf("(") > -1 || oColNm.indexOf(")") > -1 || (oColNm.toLowerCase().indexOf("case") > -1 && oColNm.toLowerCase().indexOf("when") > -1)) {
								 oGroupByColl.add("("+oColNm.replaceAll("\"", "")+")");
							 }else {
								 oGroupByColl.add(oTblNm+"."+oColNm);
							 }
						 }
							
	
					}
					

			} 
			}
		}
		
		return oGroupByColl;
		
	}
	
	public String CubeOrderByClause(String aDBMSType,
									ArrayList<SelectCubeOrder> aDt,
									ArrayList<TblAlias> aDtTblAlias)
	{
		String sOrderBy = "";
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(SelectCubeOrder oDr : aDt)
		{
			String sTblNm = oDr.getTBL_NM();
			String sColNm = ColumnAliasNm(aDBMSType, oDr.getTBL_NM());
			
			if(aDtTblAlias.size() > 0)
			{
				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("UNI_NM");
				condition.setConditionValue(oDr.getPARENT_UNI_NM());
				conArray.add(condition);
				
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("TBL_NM");
				condition.setConditionValue(oDr.getTBL_NM());
				conArray.add(condition);
				
				ArrayList<TblAlias> oAliasRows = Select(aDtTblAlias,conArray);
				
				if(oAliasRows.size() > 0)
					if(sTblNm.equalsIgnoreCase(oAliasRows.get(0).getALIAS_TBL_NM()))
						sTblNm = oAliasRows.get(0).getALIAS_TBL_NM();
				
				if(sOrderBy == "")
					sOrderBy = "ORDER BY " + "\t" + sTblNm + "." + sColNm + " " + oDr.getSORT_TYPE();
				else
					sOrderBy = sOrderBy + "," + vbCrLf + "\t" + sTblNm + "." + sColNm + " " + oDr.getSORT_TYPE();
			}
			
		}
		
		if(aDBMSType.equalsIgnoreCase("MS-SQL") && sOrderBy != "")
			sOrderBy = sOrderBy + vbCrLf + "\t" + " OFFSET 0 ROW";
		
		return sOrderBy;
	}
	
	public ArrayList<String> CubeUniOnSelClause(String aDBMSType,
												ArrayList<SelectCube> aDtSel,
												ArrayList<Hierarchy> aDtSelHie,
												ArrayList<SelectCubeMeasure> aDtSelMea)
	{
			ArrayList<String> oSelClauseColl = new ArrayList<String>();
			ArrayList<Condition> conArray = new ArrayList<Condition>();
			Condition condition = new Condition();
			
			for(SelectCube oDr : aDtSel)
			{
				String sCaption = oDr.getCAPTION();
				
				if(oDr.getTYPE().equalsIgnoreCase("MEA"))
				{
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("MEA_UNI_NM");
					condition.setConditionValue(oDr.getUNI_NM());
					conArray.add(condition);
					
					ArrayList<SelectCubeMeasure> oRows = Select(aDtSelMea,conArray);
					
					oSelClauseColl.add("Sum" + "(" + ColumnAliasNm(aDBMSType, sCaption) + ") AS " + ColumnAliasNm(aDBMSType, sCaption));
				}
				else if(oDr.getTYPE().equalsIgnoreCase("DIM"))
				{
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("HIE_UNI_NM");
					condition.setConditionValue(oDr.getUNI_NM());
					conArray.add(condition);
					
					ArrayList<SelectCubeMeasure> oRows = Select(aDtSelMea,conArray);
					
					oSelClauseColl.add(ColumnAliasNm(aDBMSType, sCaption) + " AS " + ColumnAliasNm(aDBMSType, sCaption));
					
//					if(oRows.size() != 1)
//						oSelClauseColl.add(ColumnAliasNm(aDBMSType, sCaption) + " AS " + ColumnAliasNm(aDBMSType, sCaption) + "_K");
				}
			}
			return oSelClauseColl;
	}
	
	public ArrayList<String> CubeUniOnGroupByByClause(String aDBMSType,ArrayList<Hierarchy> aDtSelHie)
	{
		ArrayList<String> oGroupByColl = new ArrayList<String>();
		
		for(Hierarchy oDr : aDtSelHie)
		{
			oGroupByColl.add(ColumnAliasNm(aDBMSType, oDr.getHIE_CAPTION()));
		}
		
		return oGroupByColl;
	}
	public String FromTblNm(ArrayList<Relation> aDt)
	{
		ArrayList<Relation> oDt = new ArrayList<Relation>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(Relation oDr : aDt)
		{
			conArray = new ArrayList<Condition>();
			condition = new Condition();
			condition.setCondition(Comparison.Equals);
			condition.setConditionColmn("FK_TBL_NM");
			condition.setConditionValue(oDr.getFK_TBL_NM());
			conArray.add(condition);
			
			ArrayList<Relation> oRows = Select(oDt,conArray);
			
			if(oRows.size() == 0)
			{
				oDt.add(oDr);
			}
		}
		
		for(Relation oDr : oDt)
		{
			conArray = new ArrayList<Condition>();
			condition = new Condition();
			condition.setCondition(Comparison.Equals);
			condition.setConditionColmn("PK_TBL_NM");
			condition.setConditionValue(oDr.getFK_TBL_NM());
			conArray.add(condition);
			
			ArrayList<Relation> oRows = Select(oDt,conArray);
			
			if(oRows.size() == 0)
				return oDr.getFK_TBL_NM();
		}
		
		return "";
	}
	
	public ArrayList<String> FromTblNmColl(ArrayList<Relation> aDt)
	{
		ArrayList<String> sFromTblColl = new ArrayList<String>();
		ArrayList<Relation> oDt = new ArrayList<Relation>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(Relation oDr : aDt)
		{
			conArray = new ArrayList<Condition>();
			condition = new Condition();
			condition.setCondition(Comparison.Equals);
			condition.setConditionColmn("FK_TBL_NM");
			condition.setConditionValue(oDr.getFK_TBL_NM());
			conArray.add(condition);
			
			ArrayList<Relation> oRows = Select(oDt,conArray);
			
			if(oRows.size() == 0)
			{
				oDt.add(oDr);
			}
		}
		
		for(Relation oDr : oDt)
		{
			conArray = new ArrayList<Condition>();
			condition = new Condition();
			condition.setCondition(Comparison.Equals);
			condition.setConditionColmn("PK_TBL_NM");
			condition.setConditionValue(oDr.getFK_TBL_NM());
			conArray.add(condition);
			
			ArrayList<Relation> oRows = Select(oDt,conArray);
			
			if(oRows.size() == 0)
			{
				sFromTblColl.add(oDr.getFK_TBL_NM());
				return sFromTblColl;
			}
		}
		
		return sFromTblColl;
	}
	public String ChkSingleTbl(ArrayList<Hierarchy> aDtSelHieCopy,
								ArrayList<SelectCubeWhere> aDtWhereCopy,
								ArrayList<SelectCubeOrder> aDtOrderCopy,
								ArrayList<String> aJoinClauseColl)
	{
		ArrayList<Hierarchy> oRows = aDtSelHieCopy;
		ArrayList<SelectCubeWhere> oRowsWhere = new ArrayList<SelectCubeWhere>();
		ArrayList<SelectCubeOrder> oRowsOrder = new ArrayList<SelectCubeOrder>();
		ArrayList<String> oTblColl = new ArrayList<String>();
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for(Hierarchy oDr : oRows)
		{
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		conArray = new ArrayList<Condition>();
		condition = new Condition();
		condition.setCondition(Comparison.Equals);
		condition.setConditionColmn("TYPE");
		condition.setConditionValue("DIM");
		conArray.add(condition);
		
		oRowsWhere = Select(aDtWhereCopy,conArray);
		
		for(SelectCubeWhere oDr : oRowsWhere)
		{
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		conArray = new ArrayList<Condition>();
		condition = new Condition();
		condition.setCondition(Comparison.Equals);
		condition.setConditionColmn("TYPE");
		condition.setConditionValue("DIM");
		conArray.add(condition);
		
		oRowsOrder = Select(aDtOrderCopy,conArray);
		
		for(SelectCubeOrder oDr : aDtOrderCopy)
		{
			if(!oTblColl.contains(oDr.getTBL_NM()))
				oTblColl.add(oDr.getTBL_NM());
		}
		
		if(oTblColl.size() == 1)
			return oTblColl.get(0);
		else
			return "";
		
	}
	public String CubeQuerySetting(ArrayList<SelectCube> aDtSel,
			ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea,
			ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder, String aDBMSType,
			ArrayList<Relation> aDtCubeRel, ArrayList<Relation> aDtDsViewRel,
			ArrayList<SelectCubeEtc> aDtEtc) {
		boolean bNonRelQuery = false;

		String sRtnQuery = "";
		String sQuery = "";
		QueryGen oQueryGen = new QueryGen();

		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<String> oJoinClauseColl = new ArrayList<String>();
		ArrayList<String> oUnionClauseColl = new ArrayList<String>();
		ArrayList<String> oNonJoinTblColl = new ArrayList<String>();
		
		String sSelClauseScript = "";
		String sWhereClauseScript = "";
		String sFromClauseScript = "";
		String sJoinClauseScript = "";
		String sGroupByClauseScript = "";
		String sHavingClauseScript = "";
		String sOrderByClauseScript = "";

		ArrayList<String> oMeaGrpColl = new ArrayList<String>();
		ArrayList<String> oDimColl = new ArrayList<String>();
		
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for (SelectCubeMeasure oDr : aDtSelMea) {
			if (!oMeaGrpColl.contains(oDr.getMEA_GRP_UNI_NM())) {
				oMeaGrpColl.add(oDr.getMEA_GRP_UNI_NM());
			}
		}

		for (Hierarchy oDr : aDtSelHIe) {
			if (!oDimColl.contains(oDr.getDIM_UNI_NM())) {
				oDimColl.add(oDr.getDIM_UNI_NM());
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("MEA")) {
				if (!oMeaGrpColl.contains(oDr.getPARENT_UNI_NM())) {
					oMeaGrpColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("DIM")) {
				if (!oDimColl.contains(oDr.getPARENT_UNI_NM())) {
					oDimColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		if (!oMeaGrpColl.isEmpty()) {
			for (String sMeaGrpNm : oMeaGrpColl) {
				String sMeaTblNm = null;
				ArrayList<SelectCubeMeasure> oMeaRows = new ArrayList<SelectCubeMeasure>();

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_GRP_UNI_NM");
				condition.setConditionValue(sMeaGrpNm);
				conArray.add(condition);

				oMeaRows.addAll((Collection<? extends SelectCubeMeasure>) Select(
						aDtSelMea, conArray));

				if (oMeaRows.size() == 0) {
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("PARENT_UNI_NM");
					condition.setConditionValue(sMeaGrpNm);
					conArray.add(condition);

					ArrayList<SelectCubeWhere> oWhereRows = (ArrayList<SelectCubeWhere>) Select(
							aDtWhere, conArray);
					sMeaTblNm = oWhereRows.get(0).getTBL_NM();
				} else {
					sMeaTblNm = oMeaRows.get(0).getMEA_TBL_NM();
				}

				oSelClauseColl.clear();
				oJoinClauseColl.clear();
				oNonJoinTblColl.clear();

				sSelClauseScript = "";
				sWhereClauseScript = "";
				sFromClauseScript = "";
				sJoinClauseScript = "";
				sGroupByClauseScript = "";
				sHavingClauseScript = "";
				// ---------------------------------------------------------------------'
				// FROM 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();
				oQueryGen.SelectFromTable(sMeaTblNm);
				sFromClauseScript = oQueryGen.BuildQueryFrom();

				// ---------------------------------------------------------------------'
				// FROM 절 종료
				// ---------------------------------------------------------------------'

				// ---------------------------------------------------------------------'
				// JOIN 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();

				ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
				ArrayList<SelectCubeMeasure> oDtSelMeaCopy = new ArrayList<SelectCubeMeasure>();

				if (oMeaRows.size() == 0) {
					oDtSelMeaCopy = aDtSelMea;
				} else {
					oDtSelMeaCopy = oMeaRows;
				}

				ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
				ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;

				/* DOGFOOT ktkang 주제영역 Join 부분에서 순서가 꼬여서 에러나는 부분 수정 시작  20200225 */
				ArrayList<Relation> oDtJoin2 = CubeJoinSetting(oDtSelHieCopy,
						oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel,
						aDtDsViewRel, true);
				
				ArrayList<TblAlias> oDtTblAlias = new ArrayList<TblAlias>();
				LinkedList<Relation> oDtJoin = new LinkedList<Relation>();
				
				ArrayList<String> pkTableList = new ArrayList<String>();
				ArrayList<Integer> pkRelationList = new ArrayList<Integer>();
				ArrayList<Integer> pkConRelationList = new ArrayList<Integer>();
				for (int i = 0; i < oDtJoin2.size(); i++) {
					if(!pkTableList.contains(oDtJoin2.get(i).getPK_TBL_ALIAS_NM())) {
						pkTableList.add(oDtJoin2.get(i).getPK_TBL_ALIAS_NM());
						oDtJoin2.get(i).setRELATION_ID(i);
						pkRelationList.add(i);
					} else {
						pkTableList.add(oDtJoin2.get(i).getPK_TBL_ALIAS_NM());
						oDtJoin2.get(i).setRELATION_ID(i);
						pkConRelationList.add(i);
					}
				}
				
				for (int pkRelation : pkRelationList) {
					for (Relation oDr : oDtJoin2) {
						if(oDr.getRELATION_ID() == pkRelation) {
							oDtJoin.add(oDr);
						}
					}
				}
				
				for (int pkRelation : pkConRelationList) {
					for (Relation oDr : oDtJoin2) {
						if(oDr.getRELATION_ID() == pkRelation) {
							oDtJoin.add(oDr);
						}
					}
				}
				/* DOGFOOT ktkang 주제영역 Join 부분에서 순서가 꼬여서 에러나는 부분 수정 끝  20200225 */
//				for(Relation odr :oDtJoin) {
//					for(aDtSelMea)
//					odr.getFK_COL_NM().equals(anObject)
//				}
				for (Relation oDr : oDtJoin) {
					String sPkTblNm = "";
					String sPkTblAlias = "";
					
					if(oDr.getPK_TBL_ALIAS_NM() != "")
					{
						sPkTblAlias = oDr.getPK_TBL_ALIAS_NM();
						
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue("[" + oDr.getPK_TBL_ALIAS_NM() + "]");
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						if(oAliasRows.size() == 0)
						{
							TblAlias oRow = new TblAlias();
							oRow.setUNI_NM(oDr.getDIM_UNI_NM());
							oRow.setTBL_NM(oDr.getPK_TBL_NM());
							oRow.setALIAS_TBL_NM(oDr.getPK_TBL_ALIAS_NM());
							
							oDtTblAlias.add(oRow);
						}
						
					}
					
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDr.getFK_TBL_NM());
					conArray.add(condition);
					
					ArrayList<TblAlias> oFkTblAliasRows = Select(oDtTblAlias,conArray);
					
					if(oFkTblAliasRows.size() > 0)
						oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oFkTblAliasRows.get(0).getALIAS_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
					else {
						//PK & FK 설정
						
						if(oDr.getEXPRESSION()!=null) {
							
							/*dogfoot shlim 20210430*/
							String FK_VALUE;
							String PK_VALUE;
							// 고용정보원 본사처리 - 주제영역 오류 begin
							if(oDr.getFK_EXPRESS()!=null && !oDr.getFK_EXPRESS().equals("")) {
								FK_VALUE = oDr.getFK_EXPRESS();
							}else {
								FK_VALUE = oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM());
							}
							
							if(oDr.getPK_EXPRESS()!=null && !oDr.getPK_EXPRESS().equals("")) {
								PK_VALUE = oDr.getPK_EXPRESS();
							}else {
								PK_VALUE = sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM());
							}
							
							for(Relation r : aDtCubeRel) {
								
								if(r.getFK_COL_NM().equals(oDr.getFK_COL_NM())) {
									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , PK_VALUE , Comparison.Equals, oDr.getFK_TBL_NM(), FK_VALUE);
									break;
								}
								else if(r.getPK_COL_NM().equals(oDr.getPK_COL_NM())) {
									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , PK_VALUE , Comparison.Equals, oDr.getFK_TBL_NM(), FK_VALUE);
									break;
								}
							}
						}
//						if(oDr.getFK_COL_NM().contains("WISE_")) {
//							for(Relation r : aDtCubeRel) {
//								if(r.getFK_COL_NM().equals(oDr.getFK_COL_NM())) {
//									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getEXPRESSION());
//									break;
//								}
//							}
//						}
//						else if(oDr.getPK_COL_NM().contains("WISE_")) {
//							for(Relation r : aDtCubeRel) {
//								if(r.getPK_COL_NM().equals(oDr.getPK_COL_NM())) {
//									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , oDr.getEXPRESSION() , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
//									break;
//								}
//							}
//						}
						else {
							/*dogfoot shlim 20210430*/
							String FK_VALUE;
							String PK_VALUE;
							// 고용정보원 본사처리 - 주제영역 오류 begin
							if(oDr.getFK_EXPRESS()!=null && !oDr.getFK_EXPRESS().equals("")) {
								FK_VALUE = oDr.getFK_EXPRESS();
							}else {
								FK_VALUE = oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM());
							}
							
							if(oDr.getPK_EXPRESS()!=null && !oDr.getPK_EXPRESS().equals("")) {
								PK_VALUE = oDr.getPK_EXPRESS();
							}else {
								PK_VALUE = sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM());
							}
							// 고용정보원 본사처리 - 주제영역 오류 end
							oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , PK_VALUE , Comparison.Equals, oDr.getFK_TBL_NM(), FK_VALUE);	
						}
						
					}
					
					if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
						oJoinClauseColl.add(oDr.getFK_TBL_NM());
					
					if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
						oJoinClauseColl.add(oDr.getPK_TBL_NM());
					
				}
				
				
				String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sMeaTblNm, oMeaGrpColl);
				
				if(sNonJoinTbl != "")
				{
					System.out.println("관계없는 테이블명 = " + sNonJoinTbl);
					bNonRelQuery = false;
					
					/* 환경변수........어찌 가져오나....조회하자....ㄴ
					 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
		                 bNonRelQuery = True
		             End If*/
				}
				
				if(sNonJoinTbl == "")
					sJoinClauseScript = oQueryGen.BuildQueryFrom();
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
				
				//---------------------------------------------------------------------'
                // SELECT 절 시작
                //---------------------------------------------------------------------'
				for(SelectCube sel : aDtSel) {
		        	System.out.println(sel.toString());
		        }
				for(Hierarchy selhie : aDtSelHIe) {
					System.out.println(selhie.toString());
				}
				oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, sMeaGrpNm, oDtTblAlias);
				for(String s : oSelClauseColl) {
					System.out.println(s);
				}
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				//---------------------------------------------------------------------'
                // SELECT 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // WHERE 절 시작
                //---------------------------------------------------------------------'
				
				String sChnCond = "";
				
				if(aDtEtc.size() > 0)
					sChnCond = aDtEtc.get(0).getCHANGE_COND();
				
				if(sChnCond == null)
					sChnCond = "";
				
				String sSubQuery = "";
				String sLogic = "";
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					oQueryGen = new QueryGen();
					
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					
					if(oDr.getAGG().equalsIgnoreCase(""))
					{
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue(oDr.getPARENT_UNI_NM());
						conArray.add(condition);
						
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("TBL_NM");
						condition.setConditionValue(oDr.getTBL_NM());
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						String sColExpress = oDr.getCOL_EXPRESS();
						String sTblNm = oDr.getTBL_NM();
						String sColNm = oDr.getCOL_NM();
						
						/*dogfoot 주제영역 필터 오류 수정 shlim 20210624*/
						// 고용정보원 본사처리 - 주제영역 오류 begin
//						if(oAliasRows.size() > 0) {
//							for(TblAlias oAliasRow : oAliasRows ) {
//								if(sTblNm.equalsIgnoreCase(oAliasRow.getTBL_NM()) && oDr.getPARENT_UNI_NM().equalsIgnoreCase(oAliasRow.getUNI_NM()) )
//									sTblNm = oAliasRow.getALIAS_TBL_NM();
//							}
//							if(sTblNm.equalsIgnoreCase(oAliasRows.get(0).getTBL_NM()))
//								sTblNm = oAliasRows.get(0).getALIAS_TBL_NM();
//						}	
						if(oAliasRows.size() > 0) {
							if(oAliasRows.size() > 1) {
								for(TblAlias oAliasRow : oAliasRows) {
									if(sTblNm.equalsIgnoreCase(oAliasRow.getTBL_NM()) && oDr.getPARENT_UNI_NM().equalsIgnoreCase(oAliasRow.getUNI_NM()))
										sTblNm = oAliasRow.getALIAS_TBL_NM();
								}
							}else{
								if(sTblNm.equalsIgnoreCase(oAliasRows.get(0).getTBL_NM()))
									sTblNm = oAliasRows.get(0).getALIAS_TBL_NM();
							}
						}
							/*dogfoot 주제영역 테이블 복사 조건절 오류 수정 shlim 20210427*/
						// 고용정보원 본사처리 - 주제영역 오류 end
						
						// 고용정보원 본사처리 - 주제영역 오류 begin
						/*dogfoot 주제영역 필터 오류 수정 shlim 20210624*/
						if(!sColExpress.equals(""))
							sFieldNm = sColExpress;
						else
							sFieldNm = sTblNm + "." + ColumnAliasNm(aDBMSType, sColNm);
						// 고용정보원 본사처리 - 주제영역 오류 end
						/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
						String sOper = oDr.getOPERATION();
						
						if(sOper == null || sOper.equals(null) || sOper.equalsIgnoreCase(""))//|| sOper.equalsIgnoreCase("LIST"))
							sOper = "In";
						
//						if(Boolean.getBoolean(oDr.getPARAM_YN()))
						if(Boolean.parseBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
						{
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
							
							if(oDr.getVALUES().equalsIgnoreCase(""))
								/*dogfoot 주제영역 계산된컬럼 필터 올렸을때 치환 기능 추가 shlim 20210408*/
								// 고용정보원 본사처리 - 주제영역 오류 begin
								if(!sColExpress.equals(""))
									sValue = sColExpress;
								else
									sValue = oDr.getVALUES_CAPTION();
								// 고용정보원 본사처리 - 주제영역 오류 end
							else
								sValue = oDr.getVALUES();
							// 고용정보원 본사처리 - 주제영역 오류 begin
//							if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") || oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
							if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") || oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]") || oDr.getVALUES().equalsIgnoreCase("[[_ALL_VALUE_],[_ALL_VALUE_]]")|| oDr.getVALUES().equalsIgnoreCase("[[_EMPTY_VALUE_],[_EMPTY_VALUE_]]"))
							// 고용정보원 본사처리 - 주제영역 오류 end
							{
								sDataType = "NUMBER";
								
								String sWhereClause = oDr.getWHERE_CLAUSE();
								
								if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
									sWhereClause = "";
								
								if(sOper.equalsIgnoreCase("Between") || sOper.equalsIgnoreCase("BETWEEN_CAND"))
								{
									if(sWhereClause.equalsIgnoreCase(""))
										sValue = sFieldNm + "," + sFieldNm;
									else
										sValue = sWhereClause + "," + sWhereClause;
								}
								else
								{
									/* DOGFOOT ajkim 주제영역 전체 오류 수정 20210222*/
									sOper = "Equals";
									if(sWhereClause.equalsIgnoreCase(""))
										/*dogfoot 주제영역 계산된컬럼 필터 올렸을때 치환 기능 추가 shlim 20210408*/
										// 고용정보원 본사처리 - 주제영역 오류 begin
										if(!sColExpress.equals("")) {
											sValue = sColExpress;
											sDataType = "STRING";
										}
										else {
											sValue = sFieldNm;	
										}
										// 고용정보원 본사처리 - 주제영역 오류 end
									else
										/*dogfoot 주제영역 계산된컬럼 필터 올렸을때 치환 기능 추가 shlim 20210408*/
										// 고용정보원 본사처리 - 주제영역 오류 begin
										if(!sColExpress.equals("")) {
											sValue = sColExpress;
											sDataType = "STRING";
										}
										else {
											sValue = sWhereClause;	
										}
										// 고용정보원 본사처리 - 주제영역 오류 end
								}
								
							}
							else
							{
								//20210427 AJKIM 주제영역 between 전체 조회되지 않는 오류 수정 dogfoot
								// 고용정보원 본사처리 - 주제영역 오류 begin
								if(sValue.indexOf("[_ALL_VALUE_]") >= 0) {
									String[] sValueArr = sValue.split(",");
									sValue = sValueArr[0].replace("[[", "").replace("]", "").replace("_ALL_VALUE_", oDr.getWHERE_CLAUSE());
									sValue += ",";
									sValue += sValueArr[1].replace("[", "").replace("]]", "").replace("_ALL_VALUE_", oDr.getWHERE_CLAUSE());	
								}
								if(sValue.indexOf("[_EMPTY_VALUE_]") >= 0) {
									String[] sValueArr = sValue.split(",");
									sValue = sValueArr[0].replace("[[", "").replace("]", "").replace("_EMPTY_VALUE_", oDr.getWHERE_CLAUSE());
									sValue += ",";
									sValue += sValueArr[1].replace("[", "").replace("]]", "").replace("_EMPTY_VALUE_", oDr.getWHERE_CLAUSE());	
								}
								// 고용정보원 본사처리 - 주제영역 오류 end
								if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
								{
									sDataType = "NUMBER";
									sSubQuery = oDr.getVALUES_CAPTION();
								}
							}
						}
						
						sLogic = oDr.getLOGIC();
						
						if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
							sLogic = "AND";
						
						oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
						String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
						sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
						/*dogfoot 주제영역 필터 오류 수정 shlim 20210624*/
						sTmpWhereClauseScript = sTmpWhereClauseScript.replace("'"+ oDr.getWHERE_CLAUSE()+"'", oDr.getWHERE_CLAUSE());
						
						if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
							if(sSubQuery != "")
								sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
						
						String sCondId = oDr.getCOND_ID();
						// 고용정보원 본사처리 - 주제영역 오류 begin
						if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
							sCondId = "";
						if(sChnCond.equals("") || sCondId.equals(""))
						{
							if(sWhereClauseScript.equals(""))
								sWhereClauseScript = sTmpWhereClauseScript;
							else
								sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
						}
						// 고용정보원 본사처리 - 주제영역 오류 end
						else
						{
							sChnCond = sChnCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
						}
					}
				}
				
				if(aDtWhere.size() > 0)
				{
					// 고용정보원 본사처리 - 주제영역 오류 begin
					if(sChnCond.equals(""))
					{
						if(!sWhereClauseScript.equals(""))
							sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
					}
					else
					{
						if(!sWhereClauseScript.equals(""))
							sWhereClauseScript = "WHERE" + "   " + sChnCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
						else
							sWhereClauseScript = "WHERE" + "   " + sChnCond;
					}
					// 고용정보원 본사처리 - 주제영역 오류 end
				}
				
				//---------------------------------------------------------------------'
                // WHERE 절 종료
                //---------------------------------------------------------------------'

                //---------------------------------------------------------------------'
                // GROUP BY 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
//				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias);
				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias,aDtSel,aDtSelMea);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				//---------------------------------------------------------------------'
                // GROUP BY 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // Having 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					// 고용정보원 본사처리 - 주제영역 오류 begin
					if(!oDr.getAGG().equals(""))
					{
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
						
						if(oDr.getVALUES().equals(""))
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(Boolean.getBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						String sHavingFldNm = "";
						
						String sOper = oDr.getOPER();
						
						if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
							sOper = "";
						
						if (sOper.equalsIgnoreCase("Distinct Count"))
							sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
						else
						{
							// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
							//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
							String aAggregetion = oDr.getAGG();
							sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
						}
						
						oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
					}
					// 고용정보원 본사처리 - 주제영역 오류 end
					
				}
				
				if(oQueryGen.get_havingStatement().size() > 0)
					sHavingClauseScript = oQueryGen.BuildQueryHaving();
				
				//---------------------------------------------------------------------'
                // Having 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 시작
                //---------------------------------------------------------------------'
				
				if(oMeaGrpColl.size() == 1)
					sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, oDtTblAlias);
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 종료
                //---------------------------------------------------------------------'
				
				sQuery = sSelClauseScript;
				// 고용정보원 본사처리 - 주제영역 오류 begin
				if(!sJoinClauseScript.equals(""))
					sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
				else
					sQuery = sQuery + vbCrLf + sFromClauseScript;
				
                if(!sWhereClauseScript.equals(""))
                	sQuery = sQuery + vbCrLf + sWhereClauseScript;
                
                if(!sGroupByClauseScript.equals(""))
                	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
                
                if(!sHavingClauseScript.equals(""))
                	sQuery = sQuery + vbCrLf + sHavingClauseScript;
                
                if(!sOrderByClauseScript.equals(""))
                	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
                // 고용정보원 본사처리 - 주제영역 오류 end
                oUnionClauseColl.add(sQuery);
			}
			if(oUnionClauseColl.size() > 1)
			{
				sQuery = "";
				
				for(String sQ : oUnionClauseColl)
				{
					if(sQuery == "")
						sQuery = sQ;
					else
						sQuery = sQuery + vbCrLf + vbCrLf + "UNION ALL" + vbCrLf + vbCrLf + sQ;
				}
				
				/* '측정값 테이블이 2개 이상이 사용 되었을 경우 각각의 측정값 테이블의 쿼리를 유니온으로 묶어서 표시 한다.
                '---------------------------------------------------------------------'
                ' UNION SELECT 절 시작
                '---------------------------------------------------------------------'*/
				
				oSelClauseColl = CubeUniOnSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				/*'---------------------------------------------------------------------'
                ' UNION SELECT 절 종료
                '---------------------------------------------------------------------'*/
				
				sRtnQuery = sSelClauseScript + vbCrLf + " FROM " + vbCrLf + "(" + vbCrLf + sQuery + vbCrLf + ") X";
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 시작
                '---------------------------------------------------------------------'*/
				
				oQueryGen = new QueryGen();
				
				ArrayList<String> oGroupByColl = CubeUniOnGroupByByClause(aDBMSType, aDtSelHIe);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				if(sGroupByClauseScript != "")
					sRtnQuery = sRtnQuery + vbCrLf + sGroupByClauseScript;
				
				sQuery = sRtnQuery;
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 종료
                '---------------------------------------------------------------------'*/
			}
			else
			{
				sRtnQuery = oUnionClauseColl.get(0);
				sQuery = sRtnQuery;
			}
			
		}//MeaGroup
		else
		{
			/*'---------------------------------------------------------------------'
            ' SELECT 절 시작
            '---------------------------------------------------------------------'*/
			
			oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, "", new ArrayList<TblAlias> ());
			
			oQueryGen = new QueryGen();
			
			oQueryGen.SelectColumns(oSelClauseColl);
			sSelClauseScript = oQueryGen.BuildQuerySelect();
			
			/*'---------------------------------------------------------------------'
            ' SELECT 절 종료
            '---------------------------------------------------------------------'*/
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 시작
            '---------------------------------------------------------------------'*/
			
			ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
			ArrayList<SelectCubeMeasure> oDtSelMeaCopy = aDtSelMea;
			ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
			ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;
			ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy, oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel, aDtDsViewRel, true);
			
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 시작
            '---------------------------------------------------------------------'*/
			
			String sFromTblNm = FromTblNm(oDtJoin);
			
			oQueryGen.SelectFromTable(sFromTblNm);
			sFromClauseScript = oQueryGen.BuildQueryFrom();
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 종료
            '---------------------------------------------------------------------'*/
			
			if(oDtJoin.size() > 0)
			{
				oQueryGen = new QueryGen();
				
				ArrayList<String> oFromTblColl = FromTblNmColl(oDtJoin);
				
				for(String oT : oFromTblColl)
				{
					boolean bTrue = true;
					String sFkTblNm = oT;
					
					do {
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("FK_TBL_NM");
						condition.setConditionValue(sFkTblNm);
						conArray.add(condition);
						//원래 TAG에 ISNULL 합수가 있음 미구현 상태라 주석
						
						/*condition.setCondition(Comparison.NotEquals);
						condition.setConditionColmn("TAG");
						condition.setConditionValue("Y");
						conArray.add(condition);*/
						
						ArrayList<Relation> oRows = Select(oDtJoin,conArray);
					
						if(oRows.size() == 0)
							bTrue = false;
						else
						{
							for(Relation oDr : oRows)
							{
								oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), 
												  oDr.getPK_TBL_NM(), 
												  oDr.getPK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()), 
												  Comparison.Equals,  
												  oDr.getFK_TBL_NM(), 
												  oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
								oDr.setTAG("Y");
								
								sFkTblNm = oDr.getPK_TBL_NM();
								
								if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
									oJoinClauseColl.add(oDr.getFK_TBL_NM());
								
								if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
									oJoinClauseColl.add(oDr.getPK_TBL_NM());
							}
						}
					
					} while (bTrue);
				}
				
				sJoinClauseScript = oQueryGen.BuildQueryFrom();
				
			}
			
			String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sFromTblNm, oMeaGrpColl);
			
			if(sNonJoinTbl != "")
			{
				System.out.println("관계없는 테이블명 = " + sNonJoinTbl);
				bNonRelQuery = false;
				
				/* 환경변수........어찌 가져오나....조회하자....ㄴ
				 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
	                 bNonRelQuery = True
	             End If*/
			}
			
			if(sNonJoinTbl != "")
			{
				/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
				if(sJoinClauseScript == "") {
					if(sFromClauseScript.trim().equals("FROM")) {
						sJoinClauseScript = sNonJoinTbl;
					} else {
						sJoinClauseScript = "," + sNonJoinTbl;
					}
				}
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
			}
			else
			{
				if(sFromTblNm == "")
					sFromClauseScript = sFromClauseScript + ChkSingleTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl);
			}
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 종료
            '---------------------------------------------------------------------'

            '---------------------------------------------------------------------'
            ' WHERE 절 시작
            '---------------------------------------------------------------------'*/
			
			String sChndCond = "";
			
			if(aDtEtc.size() > 0)
				sChndCond = aDtEtc.get(0).getCHANGE_COND();
			
			if (sChndCond == null)
				sChndCond = "";
			
			String sSubQuery = "";
			String sLogic = "";
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				oQueryGen = new QueryGen();
				
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG().equalsIgnoreCase(""))
				{
					
					if(oDr.getCOL_EXPRESS() != "")
						sFieldNm = oDr.getCOL_EXPRESS();
					else
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					 /* DOGFOOT ktkang 주제영역 필터 오류 수정  20200709 */
					String sOper = oDr.getOPERATION();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "In";
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
					{
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						if(oDr.getVALUES().equalsIgnoreCase(""))
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") ||  oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
						{
							sDataType = "NUMBER";
							
							String sWhereClause = oDr.getWHERE_CLAUSE();
							
							if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
								sWhereClause = "";
							
							if(sOper.equalsIgnoreCase("Between"))
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm + "," + sFieldNm;
								else
									sValue = sWhereClause + "," + sWhereClause;
							}
							else
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm;
								else
									sValue = sWhereClause;
							}
							
						}
						else
						{
							if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
							{
								sDataType = "NUMBER";
								sSubQuery = oDr.getVALUES_CAPTION();
							}
						}
					}
					
					sLogic = oDr.getLOGIC();
					
					if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
						sLogic = "AND";
					
					oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
					String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
					sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
					
					if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
						if(sSubQuery != "")
							sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
					
					String sCondId = oDr.getCOND_ID();
					
					if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
						sCondId = "";
					
					if(sChndCond == "" || sCondId == "")
					{
						if(sWhereClauseScript == "")
							sWhereClauseScript = sTmpWhereClauseScript;
						else
							sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
					}
					else
					{
						sChndCond = sChndCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
					}
				}
			}
			
			if(aDtWhere.size() > 0)
			{
				if(sChndCond == "")
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
				}
				else
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sChndCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
					else
						sWhereClauseScript = "WHERE" + "   " + sChndCond;
				}
			}
			
			//---------------------------------------------------------------------'
            // WHERE 절 종료
            //---------------------------------------------------------------------'

            //---------------------------------------------------------------------'
            // GROUP BY 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
			ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,new ArrayList<TblAlias> (), aDtSel, aDtSelMea);
//			ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,new ArrayList<TblAlias> ());
			if(oGroupByColl.size() > 0)
			{
				oQueryGen.GroupBy(oGroupByColl);
				sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
			}
			
			//---------------------------------------------------------------------'
            // GROUP BY 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // Having 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG() == "MEA")
				{
					sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					if(oDr.getVALUES() == "")
						sValue = oDr.getVALUES_CAPTION();
					else
						sValue = oDr.getVALUES();
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
					
					String sHavingFldNm = "";
					
					String sOper = oDr.getOPER();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "";
					
					if (sOper.equalsIgnoreCase("Distinct Count"))
						sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
					else
					{
						// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
						//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
						String aAggregetion = oDr.getAGG();
						sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
					}
					
					oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
				}
				
			}
			
			if(oQueryGen.get_havingStatement().size() > 0)
				sHavingClauseScript = oQueryGen.BuildQueryHaving();
			
			//---------------------------------------------------------------------'
            // Having 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 시작
            //---------------------------------------------------------------------'
			
			if(oMeaGrpColl.size() == 1)
				sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, new ArrayList<TblAlias> ());
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 종료
            //---------------------------------------------------------------------'
			
			sQuery = sSelClauseScript;
			
			if(sJoinClauseScript != "")
				sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
			else
				sQuery = sQuery + vbCrLf + sFromClauseScript;
			
            if(sWhereClauseScript != "")
            	sQuery = sQuery + vbCrLf + sWhereClauseScript;
            
            if(sGroupByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
            
            if(sHavingClauseScript != "")
            	sQuery = sQuery + vbCrLf + sHavingClauseScript;
            
            if(sOrderByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
            
		}
		
		 if(bNonRelQuery)
		 {
			 System.out.println("REL ERROR" + vbCrLf + sQuery);
			 return "REL ERROR";
		 }
		 else
			 return sQuery;
		 
	}
	
	public String CubeQuerySetting(ArrayList<SelectCube> aDtSel,
			ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea,
			ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder, String aDBMSType,
			ArrayList<Relation> aDtCubeRel, ArrayList<Relation> aDtDsViewRel,
			ArrayList<SelectCubeEtc> aDtEtc,String allowNonTBLYN) {
		boolean bNonRelQuery = false;
		
		String sRtnQuery = "";
		String sQuery = "";
		QueryGen oQueryGen = new QueryGen();

		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<String> oJoinClauseColl = new ArrayList<String>();
		ArrayList<String> oUnionClauseColl = new ArrayList<String>();
		ArrayList<String> oNonJoinTblColl = new ArrayList<String>();
		
		String sSelClauseScript = "";
		String sWhereClauseScript = "";
		String sFromClauseScript = "";
		String sJoinClauseScript = "";
		String sGroupByClauseScript = "";
		String sHavingClauseScript = "";
		String sOrderByClauseScript = "";

		ArrayList<String> oMeaGrpColl = new ArrayList<String>();
		ArrayList<String> oDimColl = new ArrayList<String>();
		
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for (SelectCubeMeasure oDr : aDtSelMea) {
			if (!oMeaGrpColl.contains(oDr.getMEA_GRP_UNI_NM())) {
				oMeaGrpColl.add(oDr.getMEA_GRP_UNI_NM());
			}
		}

		for (Hierarchy oDr : aDtSelHIe) {
			if (!oDimColl.contains(oDr.getDIM_UNI_NM())) {
				oDimColl.add(oDr.getDIM_UNI_NM());
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("MEA")) {
				if (!oMeaGrpColl.contains(oDr.getPARENT_UNI_NM())) {
					oMeaGrpColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("DIM")) {
				if (!oDimColl.contains(oDr.getPARENT_UNI_NM())) {
					oDimColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		if (!oMeaGrpColl.isEmpty()) {
			for (String sMeaGrpNm : oMeaGrpColl) {
				String sMeaTblNm = null;
				ArrayList<SelectCubeMeasure> oMeaRows = new ArrayList<SelectCubeMeasure>();

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_GRP_UNI_NM");
				condition.setConditionValue(sMeaGrpNm);
				conArray.add(condition);

				oMeaRows.addAll((Collection<? extends SelectCubeMeasure>) Select(
						aDtSelMea, conArray));

				if (oMeaRows.size() == 0) {
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("PARENT_UNI_NM");
					condition.setConditionValue(sMeaGrpNm);
					conArray.add(condition);

					ArrayList<SelectCubeWhere> oWhereRows = (ArrayList<SelectCubeWhere>) Select(
							aDtWhere, conArray);
					sMeaTblNm = oWhereRows.get(0).getTBL_NM();
				} else {
					sMeaTblNm = oMeaRows.get(0).getMEA_TBL_NM();
				}

				oSelClauseColl.clear();
				oJoinClauseColl.clear();
				oNonJoinTblColl.clear();

				sSelClauseScript = "";
				sWhereClauseScript = "";
				sFromClauseScript = "";
				sJoinClauseScript = "";
				sGroupByClauseScript = "";
				sHavingClauseScript = "";
				// ---------------------------------------------------------------------'
				// FROM 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();
				oQueryGen.SelectFromTable(sMeaTblNm);
				sFromClauseScript = oQueryGen.BuildQueryFrom();

				// ---------------------------------------------------------------------'
				// FROM 절 종료
				// ---------------------------------------------------------------------'

				// ---------------------------------------------------------------------'
				// JOIN 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();

				ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
				ArrayList<SelectCubeMeasure> oDtSelMeaCopy = new ArrayList<SelectCubeMeasure>();

				if (oMeaRows.size() == 0) {
					oDtSelMeaCopy = aDtSelMea;
				} else {
					oDtSelMeaCopy = oMeaRows;
				}

				ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
				ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;

				ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy,
						oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel,
						aDtDsViewRel, true);
				
				ArrayList<TblAlias> oDtTblAlias = new ArrayList<TblAlias>();
//				for(Relation odr :oDtJoin) {
//					for(aDtSelMea)
//					odr.getFK_COL_NM().equals(anObject)
//				}
				for (Relation oDr : oDtJoin) {
					String sPkTblNm = "";
					String sPkTblAlias = "";
					
//					if(oDr.getPK_TBL_ALIAS_NM() != "")
					if(!oDr.getPK_TBL_ALIAS_NM().equals(""))
					{
						sPkTblAlias = oDr.getPK_TBL_ALIAS_NM();
						
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue("[" + oDr.getPK_TBL_ALIAS_NM() + "]");
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						if(oAliasRows.size() == 0)
						{
							TblAlias oRow = new TblAlias();
							oRow.setUNI_NM(oDr.getDIM_UNI_NM());
							oRow.setTBL_NM(oDr.getPK_TBL_NM());
							oRow.setALIAS_TBL_NM(oDr.getPK_TBL_ALIAS_NM());
							
							oDtTblAlias.add(oRow);
						}
						
					}
					
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDr.getFK_TBL_NM());
					conArray.add(condition);
					
					ArrayList<TblAlias> oFkTblAliasRows = Select(oDtTblAlias,conArray);
					
					if(oFkTblAliasRows.size() > 0)
						oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oFkTblAliasRows.get(0).getALIAS_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
					else {
						//PK & FK 설정
						
						if(oDr.getEXPRESSION()!=null) {
							for(Relation r : aDtCubeRel) {
								if(r.getFK_COL_NM().equals(oDr.getFK_COL_NM())) {
									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getEXPRESSION());
									break;
								}
								else if(r.getPK_COL_NM().equals(oDr.getPK_COL_NM())) {
									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , oDr.getEXPRESSION() , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
									break;
								}
							}
						}
//						if(oDr.getFK_COL_NM().contains("WISE_")) {
//							for(Relation r : aDtCubeRel) {
//								if(r.getFK_COL_NM().equals(oDr.getFK_COL_NM())) {
//									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getEXPRESSION());
//									break;
//								}
//							}
//						}
//						else if(oDr.getPK_COL_NM().contains("WISE_")) {
//							for(Relation r : aDtCubeRel) {
//								if(r.getPK_COL_NM().equals(oDr.getPK_COL_NM())) {
//									oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , oDr.getEXPRESSION() , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
//									break;
//								}
//							}
//						}
						else {
							oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));	
						}
						
					}
					
					if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
						oJoinClauseColl.add(oDr.getFK_TBL_NM());
					
					if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
						oJoinClauseColl.add(oDr.getPK_TBL_NM());
					
				}
				
				
				String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sMeaTblNm, oMeaGrpColl);
				
				if(sNonJoinTbl != "")
				{
					System.out.println("관계없는 테이블명 in allowNonTBLYN = " + sNonJoinTbl);
//					bNonRelQuery = false;
					bNonRelQuery = allowNonTBLYN.equals("N") ? true : false; 
					/* 환경변수........어찌 가져오나....조회하자....ㄴ
					 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
		                 bNonRelQuery = True
		             End If*/
				}
				
				if(sNonJoinTbl == "")
					sJoinClauseScript = oQueryGen.BuildQueryFrom();
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
				
				//---------------------------------------------------------------------'
                // SELECT 절 시작
                //---------------------------------------------------------------------'
				oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, sMeaGrpNm, oDtTblAlias);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				//---------------------------------------------------------------------'
                // SELECT 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // WHERE 절 시작
                //---------------------------------------------------------------------'
				
				String sChnCond = "";
				
				if(aDtEtc.size() > 0)
					sChnCond = aDtEtc.get(0).getCHANGE_COND();
				
				if(sChnCond == null)
					sChnCond = "";
				
				String sSubQuery = "";
				String sLogic = "";
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					oQueryGen = new QueryGen();
					
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					
					if(oDr.getAGG().equalsIgnoreCase(""))
					{
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue(oDr.getPARENT_UNI_NM());
						conArray.add(condition);
						
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("TBL_NM");
						condition.setConditionValue(oDr.getTBL_NM());
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						String sColExpress = oDr.getCOL_EXPRESS();
						String sTblNm = oDr.getTBL_NM();
						String sColNm = oDr.getCOL_NM();
						
						if(oAliasRows.size() > 0)
							if(sTblNm.equalsIgnoreCase(oAliasRows.get(0).getTBL_NM()))
								sTblNm = oAliasRows.get(0).getALIAS_TBL_NM();
						
						if(sColExpress != "")
							sFieldNm = sColExpress;
						else
							sFieldNm = sTblNm + "." + ColumnAliasNm(aDBMSType, sColNm);
						
						/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
						String sOper = oDr.getOPERATION();
						
						if(sOper == null || sOper.equals(null) || sOper.equalsIgnoreCase(""))//|| sOper.equalsIgnoreCase("LIST"))
							sOper = "In";
						
						if(Boolean.parseBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
						{
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
							
							if(oDr.getVALUES().equalsIgnoreCase(""))
								sValue = oDr.getVALUES_CAPTION();
							else
								sValue = oDr.getVALUES();
							
							if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") || oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
							{
								sDataType = "NUMBER";
								
								String sWhereClause = oDr.getWHERE_CLAUSE();
								
								if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
									sWhereClause = "";
								
								if(sOper.equalsIgnoreCase("Between") || sOper.equalsIgnoreCase("BETWEEN_CAND"))
								{
									if(sWhereClause.equalsIgnoreCase(""))
										sValue = sFieldNm + "," + sFieldNm;
									else
										sValue = sWhereClause + "," + sWhereClause;
								}
								else
								{
									if(sWhereClause.equalsIgnoreCase(""))
										sValue = sFieldNm;
									else
										sValue = sWhereClause;
								}
								
							}
							else
							{
								if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
								{
									sDataType = "NUMBER";
									sSubQuery = oDr.getVALUES_CAPTION();
								}
							}
						}
						
						sLogic = oDr.getLOGIC();
						
						if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
							sLogic = "AND";
						
						oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
						String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
						sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
						
						if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
							if(sSubQuery != "")
								sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
						
						String sCondId = oDr.getCOND_ID();
						
						if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
							sCondId = "";
						
						if(sChnCond.equalsIgnoreCase("") || sCondId.equalsIgnoreCase(""))
						{
							if(sWhereClauseScript == "")
								sWhereClauseScript = sTmpWhereClauseScript;
							else
								sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
						}
						else
						{
							sChnCond = sChnCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
						}
					}
				}
				
				if(aDtWhere.size() > 0)
				{
					if(sChnCond.equalsIgnoreCase(""))
					{
						if(sWhereClauseScript != "")
							sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
					}
					else
					{
						if(sWhereClauseScript != "")
							sWhereClauseScript = "WHERE" + "   " + sChnCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
						else
							sWhereClauseScript = "WHERE" + "   " + sChnCond;
					}
				}
				
				//---------------------------------------------------------------------'
                // WHERE 절 종료
                //---------------------------------------------------------------------'

                //---------------------------------------------------------------------'
                // GROUP BY 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias, aDtSel, aDtSelMea);
//				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias);
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				//---------------------------------------------------------------------'
                // GROUP BY 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // Having 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					
					if(!oDr.getAGG().equalsIgnoreCase(""))
					{
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
						
						if(oDr.getVALUES().equalsIgnoreCase(""))
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(Boolean.getBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						String sHavingFldNm = "";
						
						String sOper = oDr.getOPER();
						
						if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
							sOper = "";
						
						if (sOper.equalsIgnoreCase("Distinct Count"))
							sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
						else
						{
							// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
							//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
							String aAggregetion = oDr.getAGG();
							sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
						}
						
						oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
					}
					
				}
				
				if(oQueryGen.get_havingStatement().size() > 0)
					sHavingClauseScript = oQueryGen.BuildQueryHaving();
				
				//---------------------------------------------------------------------'
                // Having 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 시작
                //---------------------------------------------------------------------'
				
				if(oMeaGrpColl.size() == 1)
					sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, oDtTblAlias);
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 종료
                //---------------------------------------------------------------------'
				
				sQuery = sSelClauseScript;
				
				if(sJoinClauseScript != "")
					sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
				else
					sQuery = sQuery + vbCrLf + sFromClauseScript;
				
                if(sWhereClauseScript != "")
                	sQuery = sQuery + vbCrLf + sWhereClauseScript;
                
                if(sGroupByClauseScript != "")
                	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
                
                if(sHavingClauseScript != "")
                	sQuery = sQuery + vbCrLf + sHavingClauseScript;
                
                if(sOrderByClauseScript != "")
                	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
                
                oUnionClauseColl.add(sQuery);
			}
			if(oUnionClauseColl.size() > 1)
			{
				sQuery = "";
				
				for(String sQ : oUnionClauseColl)
				{
					if(sQuery == "")
						sQuery = sQ;
					else
						sQuery = sQuery + vbCrLf + vbCrLf + "UNION ALL" + vbCrLf + vbCrLf + sQ;
				}
				
				/* '측정값 테이블이 2개 이상이 사용 되었을 경우 각각의 측정값 테이블의 쿼리를 유니온으로 묶어서 표시 한다.
                '---------------------------------------------------------------------'
                ' UNION SELECT 절 시작
                '---------------------------------------------------------------------'*/
				
				oSelClauseColl = CubeUniOnSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				/*'---------------------------------------------------------------------'
                ' UNION SELECT 절 종료
                '---------------------------------------------------------------------'*/
				
				sRtnQuery = sSelClauseScript + vbCrLf + " FROM " + vbCrLf + "(" + vbCrLf + sQuery + vbCrLf + ") X";
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 시작
                '---------------------------------------------------------------------'*/
				
				oQueryGen = new QueryGen();
				
				ArrayList<String> oGroupByColl = CubeUniOnGroupByByClause(aDBMSType, aDtSelHIe);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				if(sGroupByClauseScript != "")
					sRtnQuery = sRtnQuery + vbCrLf + sGroupByClauseScript;
				
				sQuery = sRtnQuery;
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 종료
                '---------------------------------------------------------------------'*/
			}
			else
			{
				sRtnQuery = oUnionClauseColl.get(0);
				sQuery = sRtnQuery;
			}
			
		}//MeaGroup
		else
		{
			/*'---------------------------------------------------------------------'
            ' SELECT 절 시작
            '---------------------------------------------------------------------'*/
			
			oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, "", new ArrayList<TblAlias> ());
			
			oQueryGen = new QueryGen();
			
			oQueryGen.SelectColumns(oSelClauseColl);
			sSelClauseScript = oQueryGen.BuildQuerySelect();
			
			/*'---------------------------------------------------------------------'
            ' SELECT 절 종료
            '---------------------------------------------------------------------'*/
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 시작
            '---------------------------------------------------------------------'*/
			
			ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
			ArrayList<SelectCubeMeasure> oDtSelMeaCopy = aDtSelMea;
			ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
			ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;
			ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy, oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel, aDtDsViewRel, true);
			
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 시작
            '---------------------------------------------------------------------'*/
			
			String sFromTblNm = FromTblNm(oDtJoin);
			
			oQueryGen.SelectFromTable(sFromTblNm);
			sFromClauseScript = oQueryGen.BuildQueryFrom();
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 종료
            '---------------------------------------------------------------------'*/
			
			if(oDtJoin.size() > 0)
			{
				oQueryGen = new QueryGen();
				
				ArrayList<String> oFromTblColl = FromTblNmColl(oDtJoin);
				
				for(String oT : oFromTblColl)
				{
					boolean bTrue = true;
					String sFkTblNm = oT;
					
					do {
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("FK_TBL_NM");
						condition.setConditionValue(sFkTblNm);
						conArray.add(condition);
						//원래 TAG에 ISNULL 합수가 있음 미구현 상태라 주석
						
						/*condition.setCondition(Comparison.NotEquals);
						condition.setConditionColmn("TAG");
						condition.setConditionValue("Y");
						conArray.add(condition);*/
						
						ArrayList<Relation> oRows = Select(oDtJoin,conArray);
					
						if(oRows.size() == 0)
							bTrue = false;
						else
						{
							for(Relation oDr : oRows)
							{
								oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), 
												  oDr.getPK_TBL_NM(), 
												  oDr.getPK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()), 
												  Comparison.Equals,  
												  oDr.getFK_TBL_NM(), 
												  oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
								oDr.setTAG("Y");
								
								sFkTblNm = oDr.getPK_TBL_NM();
								
								if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
									oJoinClauseColl.add(oDr.getFK_TBL_NM());
								
								if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
									oJoinClauseColl.add(oDr.getPK_TBL_NM());
							}
						}
					
					} while (bTrue);
				}
				
				sJoinClauseScript = oQueryGen.BuildQueryFrom();
				
			}
			
			String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sFromTblNm, oMeaGrpColl);
			
			if(sNonJoinTbl != "")
			{
				System.out.println("관계없는 테이블명 = " + sNonJoinTbl);
				bNonRelQuery = false;
				
				/* 환경변수........어찌 가져오나....조회하자....ㄴ
				 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
	                 bNonRelQuery = True
	             End If*/
			}
			
			if(sNonJoinTbl != "")
			{
				if(sJoinClauseScript == "")
					sJoinClauseScript = "," + sNonJoinTbl;
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
			}
			else
			{
				if(sFromTblNm == "")
					sFromClauseScript = sFromClauseScript + ChkSingleTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl);
			}
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 종료
            '---------------------------------------------------------------------'

            '---------------------------------------------------------------------'
            ' WHERE 절 시작
            '---------------------------------------------------------------------'*/
			
			String sChndCond = "";
			
			if(aDtEtc.size() > 0)
				sChndCond = aDtEtc.get(0).getCHANGE_COND();
			
			if (sChndCond == null)
				sChndCond = "";
			
			String sSubQuery = "";
			String sLogic = "";
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				oQueryGen = new QueryGen();
				
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG().equalsIgnoreCase(""))
				{
					
					if(oDr.getCOL_EXPRESS() != "")
						sFieldNm = oDr.getCOL_EXPRESS();
					else
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					String sOper = oDr.getOPERATION();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "In";
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
					{
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						if(oDr.getVALUES().equalsIgnoreCase(""))
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") ||  oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
						{
							sDataType = "NUMBER";
							
							String sWhereClause = oDr.getWHERE_CLAUSE();
							
							if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
								sWhereClause = "";
							
							if(sOper.equalsIgnoreCase("Between"))
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm + "," + sFieldNm;
								else
									sValue = sWhereClause + "," + sWhereClause;
							}
							else
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm;
								else
									sValue = sWhereClause;
							}
							
						}
						else
						{
							if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
							{
								sDataType = "NUMBER";
								sSubQuery = oDr.getVALUES_CAPTION();
							}
						}
					}
					
					sLogic = oDr.getLOGIC();
					
					if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
						sLogic = "AND";
					
					oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
					String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
					sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
					
					if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
						if(sSubQuery != "")
							sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
					
					String sCondId = oDr.getCOND_ID();
					
					if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
						sCondId = "";
					
					if(sChndCond == "" || sCondId == "")
					{
						if(sWhereClauseScript == "")
							sWhereClauseScript = sTmpWhereClauseScript;
						else
							sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
					}
					else
					{
						sChndCond = sChndCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
					}
				}
			}
			
			if(aDtWhere.size() > 0)
			{
				if(sChndCond == "")
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
				}
				else
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sChndCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
					else
						sWhereClauseScript = "WHERE" + "   " + sChndCond;
				}
			}
			
			//---------------------------------------------------------------------'
            // WHERE 절 종료
            //---------------------------------------------------------------------'

            //---------------------------------------------------------------------'
            // GROUP BY 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
			ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,new ArrayList<TblAlias> (), aDtSel, aDtSelMea);
			
			if(oGroupByColl.size() > 0)
			{
				oQueryGen.GroupBy(oGroupByColl);
				sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
			}
			
			//---------------------------------------------------------------------'
            // GROUP BY 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // Having 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG() == "MEA")
				{
					sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					if(oDr.getVALUES() == "")
						sValue = oDr.getVALUES_CAPTION();
					else
						sValue = oDr.getVALUES();
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
					
					String sHavingFldNm = "";
					
					String sOper = oDr.getOPER();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "";
					
					if (sOper.equalsIgnoreCase("Distinct Count"))
						sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
					else
					{
						// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
						//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
						String aAggregetion = oDr.getAGG();
						sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
					}
					
					oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
				}
				
			}
			
			if(oQueryGen.get_havingStatement().size() > 0)
				sHavingClauseScript = oQueryGen.BuildQueryHaving();
			
			//---------------------------------------------------------------------'
            // Having 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 시작
            //---------------------------------------------------------------------'
			
			if(oMeaGrpColl.size() == 1)
				sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, new ArrayList<TblAlias> ());
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 종료
            //---------------------------------------------------------------------'
			
			sQuery = sSelClauseScript;
			
			if(sJoinClauseScript != "")
				sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
			else
				sQuery = sQuery + vbCrLf + sFromClauseScript;
			
            if(sWhereClauseScript != "")
            	sQuery = sQuery + vbCrLf + sWhereClauseScript;
            
            if(sGroupByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
            
            if(sHavingClauseScript != "")
            	sQuery = sQuery + vbCrLf + sHavingClauseScript;
            
            if(sOrderByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
            
		}
		
		 if(bNonRelQuery)
		 {
			 System.out.println("REL ERROR" + vbCrLf + sQuery);
			 return "REL ERROR";
		 }
		 else
			 return sQuery;
	}
	public String CubeQuerySpecificSetting(ArrayList<SelectCube> aDtSel,
			ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea,
			ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder, String aDBMSType,
			ArrayList<Relation> aDtCubeRel, ArrayList<Relation> aDtDsViewRel,
			ArrayList<SelectCubeEtc> aDtEtc, String rollUpYn) {
		boolean bNonRelQuery = false;

		String sRtnQuery = "";
		String sQuery = "";
		QueryGen oQueryGen = new QueryGen();

		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<String> oJoinClauseColl = new ArrayList<String>();
		ArrayList<String> oUnionClauseColl = new ArrayList<String>();
		ArrayList<String> oNonJoinTblColl = new ArrayList<String>();
		
		String sSelClauseScript = "";
		String sWhereClauseScript = "";
		String sFromClauseScript = "";
		String sJoinClauseScript = "";
		String sGroupByClauseScript = "";
		String sHavingClauseScript = "";
		String sOrderByClauseScript = "";

		ArrayList<String> oMeaGrpColl = new ArrayList<String>();
		ArrayList<String> oDimColl = new ArrayList<String>();
		
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for (SelectCubeMeasure oDr : aDtSelMea) {
			if (!oMeaGrpColl.contains(oDr.getMEA_GRP_UNI_NM())) {
				oMeaGrpColl.add(oDr.getMEA_GRP_UNI_NM());
			}
		}

		for (Hierarchy oDr : aDtSelHIe) {
			if (!oDimColl.contains(oDr.getDIM_UNI_NM())) {
				oDimColl.add(oDr.getDIM_UNI_NM());
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("MEA")) {
				if (!oMeaGrpColl.contains(oDr.getPARENT_UNI_NM())) {
					oMeaGrpColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		for (SelectCubeWhere oDr : aDtWhere) {
			if (oDr.getTYPE().equals("DIM")) {
				if (!oDimColl.contains(oDr.getPARENT_UNI_NM())) {
					oDimColl.add(oDr.getPARENT_UNI_NM());
				}
			}
		}

		if (!oMeaGrpColl.isEmpty()) {
			for (String sMeaGrpNm : oMeaGrpColl) {
				String sMeaTblNm = null;
				ArrayList<SelectCubeMeasure> oMeaRows = new ArrayList<SelectCubeMeasure>();

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_GRP_UNI_NM");
				condition.setConditionValue(sMeaGrpNm);
				conArray.add(condition);

				oMeaRows.addAll((Collection<? extends SelectCubeMeasure>) Select(
						aDtSelMea, conArray));

				if (oMeaRows.size() == 0) {
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("PARENT_UNI_NM");
					condition.setConditionValue(sMeaGrpNm);
					conArray.add(condition);

					ArrayList<SelectCubeWhere> oWhereRows = (ArrayList<SelectCubeWhere>) Select(
							aDtWhere, conArray);
					sMeaTblNm = oWhereRows.get(0).getTBL_NM();
				} else {
					sMeaTblNm = oMeaRows.get(0).getMEA_TBL_NM();
				}

				oSelClauseColl.clear();
				oJoinClauseColl.clear();
				oNonJoinTblColl.clear();

				sSelClauseScript = "";
				sWhereClauseScript = "";
				sFromClauseScript = "";
				sJoinClauseScript = "";
				sGroupByClauseScript = "";
				sHavingClauseScript = "";
				// ---------------------------------------------------------------------'
				// FROM 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();
				oQueryGen.SelectFromTable(sMeaTblNm);
				sFromClauseScript = oQueryGen.BuildQueryFrom();

				// ---------------------------------------------------------------------'
				// FROM 절 종료
				// ---------------------------------------------------------------------'

				// ---------------------------------------------------------------------'
				// JOIN 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();

				ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
				ArrayList<SelectCubeMeasure> oDtSelMeaCopy = new ArrayList<SelectCubeMeasure>();

				if (oMeaRows.size() == 0) {
					oDtSelMeaCopy = aDtSelMea;
				} else {
					oDtSelMeaCopy = oMeaRows;
				}

				ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
				ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;

				ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy,
						oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel,
						aDtDsViewRel, true);
				
				ArrayList<TblAlias> oDtTblAlias = new ArrayList<TblAlias>();
				
				for (Relation oDr : oDtJoin) {
					
					System.out.println(oDr.getCONST_NM());
					
					String sPkTblNm = "";
					String sPkTblAlias = "";
					
					if(oDr.getPK_TBL_ALIAS_NM() != "")
					{
						sPkTblAlias = oDr.getPK_TBL_ALIAS_NM();
						
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue("[" + oDr.getPK_TBL_ALIAS_NM() + "]");
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						if(oAliasRows.size() == 0)
						{
							TblAlias oRow = new TblAlias();
							oRow.setUNI_NM(oDr.getDIM_UNI_NM());
							oRow.setTBL_NM(oDr.getPK_TBL_NM());
							oRow.setALIAS_TBL_NM(oDr.getPK_TBL_ALIAS_NM());
							
							oDtTblAlias.add(oRow);
						}
						
					}
					
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("TBL_NM");
					condition.setConditionValue(oDr.getFK_TBL_NM());
					conArray.add(condition);
					
					ArrayList<TblAlias> oFkTblAliasRows = Select(oDtTblAlias,conArray);
					
					if(oFkTblAliasRows.size() > 0)
						oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oFkTblAliasRows.get(0).getALIAS_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
					else
						oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), oDr.getPK_TBL_NM() + " " + sPkTblAlias , sPkTblAlias + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()) , Comparison.Equals, oDr.getFK_TBL_NM(), oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
					
					if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
						oJoinClauseColl.add(oDr.getFK_TBL_NM());
					
					if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
						oJoinClauseColl.add(oDr.getPK_TBL_NM());
					
				}
				
				
				String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sMeaTblNm, oMeaGrpColl);
				
				if(sNonJoinTbl != "")
				{
					System.out.println("관계없는 테이블명 = " + sNonJoinTbl);
					bNonRelQuery = false;
					
					/* 환경변수........어찌 가져오나....조회하자....ㄴ
					 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
		                 bNonRelQuery = True
		             End If*/
				}
				
				if(sNonJoinTbl == "")
					sJoinClauseScript = oQueryGen.BuildQueryFrom();
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
				
				//---------------------------------------------------------------------'
                // SELECT 절 시작
                //---------------------------------------------------------------------'
				
				oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, sMeaGrpNm, oDtTblAlias);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				//---------------------------------------------------------------------'
                // SELECT 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // WHERE 절 시작
                //---------------------------------------------------------------------'
				
				String sChnCond = "";
				
				if(aDtEtc.size() > 0)
					sChnCond = aDtEtc.get(0).getCHANGE_COND();
				
				if(sChnCond == null)
					sChnCond = "";
				
				String sSubQuery = "";
				String sLogic = "";
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					oQueryGen = new QueryGen();
					
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					
					if(oDr.getAGG().equalsIgnoreCase(""))
					{
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("UNI_NM");
						condition.setConditionValue(oDr.getPARENT_UNI_NM());
						conArray.add(condition);
						
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("TBL_NM");
						condition.setConditionValue(oDr.getTBL_NM());
						conArray.add(condition);
						
						ArrayList<TblAlias> oAliasRows = Select(oDtTblAlias,conArray);
						
						String sColExpress = oDr.getCOL_EXPRESS();
						String sTblNm = oDr.getTBL_NM();
						String sColNm = oDr.getCOL_NM();
						
						if(oAliasRows.size() > 0)
							if(sTblNm.equalsIgnoreCase(oAliasRows.get(0).getTBL_NM()))
								sTblNm = oAliasRows.get(0).getALIAS_TBL_NM();
						
						if(sColExpress != "")
							sFieldNm = sColExpress;
						else
							sFieldNm = sTblNm + "." + ColumnAliasNm(aDBMSType, sColNm);
						
						String sOper = oDr.getOPERATION();
						
						if(sOper.equals(null) || sOper.equalsIgnoreCase("") || sOper.equalsIgnoreCase("LIST"))
							sOper = "In";
						
						if(Boolean.getBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
						{
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
							
							if(oDr.getVALUES().equalsIgnoreCase(""))
								sValue = oDr.getVALUES_CAPTION();
							else
								sValue = oDr.getVALUES();
							
							if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") || oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
							{ 
								sDataType = "NUMBER";
								
								String sWhereClause = oDr.getWHERE_CLAUSE();
								
								if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
									sWhereClause = "";
								
								if(sOper.equalsIgnoreCase("Between") || sOper.equalsIgnoreCase("BETWEEN_CAND") || sOper.equalsIgnoreCase("BETWEEN_LIST") || sOper.equalsIgnoreCase("BETWEEN_INPUT"))
								{
									if(sWhereClause.equalsIgnoreCase(""))
										sValue = sFieldNm + "," + sFieldNm;
									else
										sValue = sWhereClause + "," + sWhereClause;
								}
								else
								{
									if(sWhereClause.equalsIgnoreCase(""))
										sValue = sFieldNm;
									else
										sValue = sWhereClause;
								}
								
							}
							else
							{
								if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
								{
									sDataType = "NUMBER";
									sSubQuery = oDr.getVALUES_CAPTION();
								}
							}
						}
						
						sLogic = oDr.getLOGIC();
						
						if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
							sLogic = "AND";
						
						oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
						String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
						sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
						
						if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
							if(sSubQuery != "")
								sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
						
						String sCondId = oDr.getCOND_ID();
						
						if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
							sCondId = "";
						
						if(sChnCond == "" || sCondId == "")
						{
							if(sWhereClauseScript == "")
								sWhereClauseScript = sTmpWhereClauseScript;
							else
								sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
						}
						else
						{
							sChnCond = sChnCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
						}
					}
				}
				
				if(aDtWhere.size() > 0)
				{
					if(sChnCond == "")
					{
						if(sWhereClauseScript != "")
							sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
					}
					else
					{
						if(sWhereClauseScript != "")
							sWhereClauseScript = "WHERE" + "   " + sChnCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
						else
							sWhereClauseScript = "WHERE" + "   " + sChnCond;
					}
				}
				
				//---------------------------------------------------------------------'
                // WHERE 절 종료
                //---------------------------------------------------------------------'

                //---------------------------------------------------------------------'
                // GROUP BY 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias, aDtSel, aDtSelMea);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupByRollup();
				}
				
				//---------------------------------------------------------------------'
                // GROUP BY 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // Having 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				
				for(SelectCubeWhere oDr : aDtWhere)
				{
					String sFieldNm = "";
					String sDataType = "";
					String sValue = "";
					
					if(oDr.getAGG() != "" )
					{
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
						
						if(oDr.getVALUES() == "")
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(Boolean.getBoolean(oDr.getPARAM_YN()))
							sDataType = "PARAM";
						else
							sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						String sHavingFldNm = "";
						
						String sOper = oDr.getOPER();
						
						if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
							sOper = "";
						
						if (sOper.equalsIgnoreCase("Distinct Count"))
							sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
						else
						{
							// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
							//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
							String aAggregetion = oDr.getAGG();
							sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
						}
						
						oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
					}
					
				}
				
				if(oQueryGen.get_havingStatement().size() > 0)
					sHavingClauseScript = oQueryGen.BuildQueryHaving();
				
				//---------------------------------------------------------------------'
                // Having 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 시작
                //---------------------------------------------------------------------'
				
				if(oMeaGrpColl.size() == 1)
					sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, oDtTblAlias);
				
				//---------------------------------------------------------------------'
                // UNION ORDER BY 절 종료
                //---------------------------------------------------------------------'
				
				sQuery = sSelClauseScript;
				
				if(sJoinClauseScript != "")
					sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
				else
					sQuery = sQuery + vbCrLf + sFromClauseScript;
				
                if(sWhereClauseScript != "")
                	sQuery = sQuery + vbCrLf + sWhereClauseScript;
                
                if(sGroupByClauseScript != "")
                	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
                
                if(sHavingClauseScript != "")
                	sQuery = sQuery + vbCrLf + sHavingClauseScript;
                
                if(sOrderByClauseScript != "")
                	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
                
                oUnionClauseColl.add(sQuery);
			}
			if(oUnionClauseColl.size() > 1)
			{
				sQuery = "";
				
				for(String sQ : oUnionClauseColl)
				{
					if(sQuery == "")
						sQuery = sQ;
					else
						sQuery = sQuery + vbCrLf + vbCrLf + "UNION ALL" + vbCrLf + vbCrLf + sQ;
				}
				
				/* '측정값 테이블이 2개 이상이 사용 되었을 경우 각각의 측정값 테이블의 쿼리를 유니온으로 묶어서 표시 한다.
                '---------------------------------------------------------------------'
                ' UNION SELECT 절 시작
                '---------------------------------------------------------------------'*/
				
				oSelClauseColl = CubeUniOnSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				/*'---------------------------------------------------------------------'
                ' UNION SELECT 절 종료
                '---------------------------------------------------------------------'*/
				
				sRtnQuery = sSelClauseScript + vbCrLf + " FROM " + vbCrLf + "(" + vbCrLf + sQuery + vbCrLf + ") X";
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 시작
                '---------------------------------------------------------------------'*/
				
				oQueryGen = new QueryGen();
				
				ArrayList<String> oGroupByColl = CubeUniOnGroupByByClause(aDBMSType, aDtSelHIe);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				if(sGroupByClauseScript != "")
					sRtnQuery = sRtnQuery + vbCrLf + sGroupByClauseScript;
				
				sQuery = sRtnQuery;
				
				/* '---------------------------------------------------------------------'
                ' UNION GROUP BY 절 종료
                '---------------------------------------------------------------------'*/
			}
			else
			{
				sRtnQuery = oUnionClauseColl.get(0);
				sQuery = sRtnQuery;
			}
			
		}//MeaGroup
		else
		{
			/*'---------------------------------------------------------------------'
            ' SELECT 절 시작
            '---------------------------------------------------------------------'*/
			
			oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, "", new ArrayList<TblAlias> ());
			
			oQueryGen = new QueryGen();
			
			oQueryGen.SelectColumns(oSelClauseColl);
			sSelClauseScript = oQueryGen.BuildQuerySelect();
			
			/*'---------------------------------------------------------------------'
            ' SELECT 절 종료
            '---------------------------------------------------------------------'*/
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 시작
            '---------------------------------------------------------------------'*/
			
			ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
			ArrayList<SelectCubeMeasure> oDtSelMeaCopy = aDtSelMea;
			ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
			ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;
			ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy, oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel, aDtDsViewRel, true);
			
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 시작
            '---------------------------------------------------------------------'*/
			
			String sFromTblNm = FromTblNm(oDtJoin);
			
			oQueryGen.SelectFromTable(sFromTblNm);
			sFromClauseScript = oQueryGen.BuildQueryFrom();
			
			/* '---------------------------------------------------------------------'
            ' FROM 절 종료
            '---------------------------------------------------------------------'*/
			
			if(oDtJoin.size() > 0)
			{
				oQueryGen = new QueryGen();
				
				ArrayList<String> oFromTblColl = FromTblNmColl(oDtJoin);
				
				for(String oT : oFromTblColl)
				{
					boolean bTrue = true;
					String sFkTblNm = oT;
					
					do {
						conArray = new ArrayList<Condition>();
						condition = new Condition();
						condition.setCondition(Comparison.Equals);
						condition.setConditionColmn("FK_TBL_NM");
						condition.setConditionValue(sFkTblNm);
						conArray.add(condition);
						//원래 TAG에 ISNULL 합수가 있음 미구현 상태라 주석
						
						/*condition.setCondition(Comparison.NotEquals);
						condition.setConditionColmn("TAG");
						condition.setConditionValue("Y");
						conArray.add(condition);*/
						
						ArrayList<Relation> oRows = Select(oDtJoin,conArray);
					
						if(oRows.size() == 0)
							bTrue = false;
						else
						{
							for(Relation oDr : oRows)
							{
								oQueryGen.AddJoin(JoinType.getJoinType(oDr.getJOIN_TYPE()), 
												  oDr.getPK_TBL_NM(), 
												  oDr.getPK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getPK_COL_NM()), 
												  Comparison.Equals,  
												  oDr.getFK_TBL_NM(), 
												  oDr.getFK_TBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getFK_COL_NM()));
								oDr.setTAG("Y");
								
								sFkTblNm = oDr.getPK_TBL_NM();
								
								if(!oJoinClauseColl.contains(oDr.getFK_TBL_NM()))
									oJoinClauseColl.add(oDr.getFK_TBL_NM());
								
								if(!oJoinClauseColl.contains(oDr.getPK_TBL_NM()))
									oJoinClauseColl.add(oDr.getPK_TBL_NM());
							}
						}
					
					} while (bTrue);
				}
				
				sJoinClauseScript = oQueryGen.BuildQueryFrom();
				
			}
			
			String sNonJoinTbl = CubeNonRelTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl, sFromTblNm, oMeaGrpColl);
			
			if(sNonJoinTbl != "")
			{
				System.out.println("관계없는 테이블명 = " + sNonJoinTbl);
				bNonRelQuery = false;
				
				/* 환경변수........어찌 가져오나....조회하자....ㄴ
				 * If m_clsSolutionProperty.GetAllowNonTblRel <> "Y" Then
	                 bNonRelQuery = True
	             End If*/
			}
			
			if(sNonJoinTbl != "")
			{
				if(sJoinClauseScript == "")
					sJoinClauseScript = "," + sNonJoinTbl;
				else
					sJoinClauseScript = oQueryGen.BuildQueryFrom() + "," + sNonJoinTbl;
			}
			else
			{
				if(sFromTblNm == "")
					sFromClauseScript = sFromClauseScript + ChkSingleTbl(oDtSelHieCopy, oDtWhereCopy, oDtOrderCopy, oJoinClauseColl);
			}
			
			/*'---------------------------------------------------------------------'
            ' JOIN 절 종료
            '---------------------------------------------------------------------'

            '---------------------------------------------------------------------'
            ' WHERE 절 시작
            '---------------------------------------------------------------------'*/
			
			String sChndCond = "";
			
			if(aDtEtc.size() > 0)
				sChndCond = aDtEtc.get(0).getCHANGE_COND();
			
			if (sChndCond == null)
				sChndCond = "";
			
			String sSubQuery = "";
			String sLogic = "";
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				oQueryGen = new QueryGen();
				
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG().equalsIgnoreCase(""))
				{
					
					if(oDr.getCOL_EXPRESS() != "")
						sFieldNm = oDr.getCOL_EXPRESS();
					else
						sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					String sOper = oDr.getOPERATION();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "In";
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
					{
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
						
						if(oDr.getVALUES().equalsIgnoreCase(""))
							sValue = oDr.getVALUES_CAPTION();
						else
							sValue = oDr.getVALUES();
						
						if(oDr.getVALUES().equalsIgnoreCase("[All]") || oDr.getVALUES().equalsIgnoreCase("[_EMPTY_VALUE_]") ||  oDr.getVALUES().equalsIgnoreCase("[_ALL_VALUE_]"))
						{
							sDataType = "NUMBER";
							
							String sWhereClause = oDr.getWHERE_CLAUSE();
							
							if(sWhereClause.equalsIgnoreCase("") || sWhereClause.equals(null))
								sWhereClause = "";
							
							if(sOper.equalsIgnoreCase("Between"))
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm + "," + sFieldNm;
								else
									sValue = sWhereClause + "," + sWhereClause;
							}
							else
							{
								if(sWhereClause.equalsIgnoreCase(""))
									sValue = sFieldNm;
								else
									sValue = sWhereClause;
							}
							
						}
						else
						{
							if(sValue.trim().equalsIgnoreCase("#SUB_QUERY#"))
							{
								sDataType = "NUMBER";
								sSubQuery = oDr.getVALUES_CAPTION();
							}
						}
					}
					
					sLogic = oDr.getLOGIC();
					
					if(sLogic.equalsIgnoreCase("") || sLogic.equals(null))
						sLogic = "AND";
					
					oQueryGen.AddWhere(sFieldNm, Comparison.getComparisonType(sOper), CheckValue(sValue),1, sDataType, oDr.getPARAM_NM(),LogicOperator.getLogicOperator(sLogic));
					String sTmpWhereClauseScript = oQueryGen.BuildQueryOnlyWhere();
					sTmpWhereClauseScript = sTmpWhereClauseScript.replace("AND" + "\t", "").trim();
					
					if (sTmpWhereClauseScript.indexOf("#SUB_QUERY#") > -1)
						if(sSubQuery != "")
							sTmpWhereClauseScript = sTmpWhereClauseScript.replace("#SUB_QUERY#", sSubQuery);
					
					String sCondId = oDr.getCOND_ID();
					
					if(sCondId.equals(null) || sCondId.equalsIgnoreCase(""))
						sCondId = "";
					
					if(sChndCond == "" || sCondId == "")
					{
						if(sWhereClauseScript == "")
							sWhereClauseScript = sTmpWhereClauseScript;
						else
							sWhereClauseScript = sWhereClauseScript + vbCrLf + "AND     " + sTmpWhereClauseScript;
					}
					else
					{
						sChndCond = sChndCond.replace("[" + oDr.getCOND_ID() + "]",sTmpWhereClauseScript);
					}
				}
			}
			
			if(aDtWhere.size() > 0)
			{
				if(sChndCond == "")
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sWhereClauseScript;
				}
				else
				{
					if(sWhereClauseScript != "")
						sWhereClauseScript = "WHERE" + "   " + sChndCond + vbCrLf + "AND" + "      " + sWhereClauseScript;
					else
						sWhereClauseScript = "WHERE" + "   " + sChndCond;
				}
			}
			
			//---------------------------------------------------------------------'
            // WHERE 절 종료
            //---------------------------------------------------------------------'

            //---------------------------------------------------------------------'
            // GROUP BY 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
			ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,new ArrayList<TblAlias> (), aDtSel, aDtSelMea);
			
			if(oGroupByColl.size() > 0)
			{
				oQueryGen.GroupBy(oGroupByColl);
				sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
			}
			
			//---------------------------------------------------------------------'
            // GROUP BY 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // Having 절 시작
            //---------------------------------------------------------------------'
			
			oQueryGen = new QueryGen();
			
			for(SelectCubeWhere oDr : aDtWhere)
			{
				String sFieldNm = "";
				String sDataType = "";
				String sValue = "";
				
				if(oDr.getAGG() == "MEA")
				{
					sFieldNm = oDr.getTBL_NM() + "." + ColumnAliasNm(aDBMSType, oDr.getCOL_NM());
					
					if(oDr.getVALUES() == "")
						sValue = oDr.getVALUES_CAPTION();
					else
						sValue = oDr.getVALUES();
					
					if(Boolean.getBoolean(oDr.getPARAM_YN()))
						sDataType = "PARAM";
					else
						sDataType = ConvertDataType(oDr.getDATA_TYPE());
					
					String sHavingFldNm = "";
					
					String sOper = oDr.getOPER();
					
					if(sOper.equals(null) || sOper.equalsIgnoreCase(""))
						sOper = "";
					
					if (sOper.equalsIgnoreCase("Distinct Count"))
						sHavingFldNm = "Count(Distinc " + sFieldNm + ")";
					else
					{
						// 원래는 있는 함수나 필요 없을것 같아 지움 GetAggregation
						//String aAggregetion = GetAggregation(aDBMSType, oDr("AGG").ToString)
						String aAggregetion = oDr.getAGG();
						sHavingFldNm = aAggregetion + "(" + sFieldNm + ")";
					}
					
					oQueryGen.AddHaving(sHavingFldNm,Comparison.getComparisonType(sOper),sValue,1,sDataType,oDr.getPARAM_NM());
				}
				
			}
			
			if(oQueryGen.get_havingStatement().size() > 0)
				sHavingClauseScript = oQueryGen.BuildQueryHaving();
			
			//---------------------------------------------------------------------'
            // Having 절 종료
            //---------------------------------------------------------------------'
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 시작
            //---------------------------------------------------------------------'
			
			if(oMeaGrpColl.size() == 1)
				sOrderByClauseScript = CubeOrderByClause(aDBMSType, aDtOrder, new ArrayList<TblAlias> ());
			
			//---------------------------------------------------------------------'
            // UNION ORDER BY 절 종료
            //---------------------------------------------------------------------'
			
			sQuery = sSelClauseScript;
			
			if(sJoinClauseScript != "")
				sQuery = sQuery + vbCrLf + sFromClauseScript + " " + sJoinClauseScript;
			else
				sQuery = sQuery + vbCrLf + sFromClauseScript;
			
            if(sWhereClauseScript != "")
            	sQuery = sQuery + vbCrLf + sWhereClauseScript;
            
            if(sGroupByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
            
            if(sHavingClauseScript != "")
            	sQuery = sQuery + vbCrLf + sHavingClauseScript;
            
            if(sOrderByClauseScript != "")
            	sQuery = sQuery + vbCrLf + sOrderByClauseScript;
            
		}
		
		 if(bNonRelQuery)
		 {
			 System.out.println("REL ERROR" + vbCrLf + sQuery);
			 return "REL ERROR";
		 }
		 else
			 return sQuery;
		 
	}
	
	public String CubeQuerySettingSingleDS(ArrayList<SelectCube> aDtSel,
			ArrayList<Hierarchy> aDtSelHIe,
			ArrayList<SelectCubeMeasure> aDtSelMea,
			ArrayList<SelectCubeWhere> aDtWhere,
			ArrayList<SelectCubeOrder> aDtOrder, String aDBMSType,
			ArrayList<Relation> aDtCubeRel, ArrayList<Relation> aDtDsViewRel,
			ArrayList<SelectCubeEtc> aDtEtc) {
		boolean bNonRelQuery = false;
		
		String sQuery = "";
		QueryGen oQueryGen = new QueryGen();

		ArrayList<String> oSelClauseColl = new ArrayList<String>();
		ArrayList<String> oSelClauseCollRename = new ArrayList<String>();
//		ArrayList<String> oJoinClauseColl = new ArrayList<String>();
		
		String sSelClauseScript = "";
		String sFromClauseScript = "";
		String sGroupByClauseScript = "";

		ArrayList<String> oMeaGrpColl = new ArrayList<String>();
		ArrayList<String> oDimColl = new ArrayList<String>();
		
		ArrayList<Condition> conArray = new ArrayList<Condition>();
		Condition condition = new Condition();
		
		for (SelectCubeMeasure oDr : aDtSelMea) {
			if (!oMeaGrpColl.contains(oDr.getMEA_GRP_UNI_NM())) {
				oMeaGrpColl.add(oDr.getMEA_GRP_UNI_NM());
			}
		}

		for (Hierarchy oDr : aDtSelHIe) {
			if (!oDimColl.contains(oDr.getDIM_UNI_NM())) {
				oDimColl.add(oDr.getDIM_UNI_NM());
			}
		}

		if (!oMeaGrpColl.isEmpty()) {
			for (String sMeaGrpNm : oMeaGrpColl) {
				String sMeaTblNm = null;
				ArrayList<SelectCubeMeasure> oMeaRows = new ArrayList<SelectCubeMeasure>();

				conArray = new ArrayList<Condition>();
				condition = new Condition();
				condition.setCondition(Comparison.Equals);
				condition.setConditionColmn("MEA_GRP_UNI_NM");
				condition.setConditionValue(sMeaGrpNm);
				conArray.add(condition);

				oMeaRows.addAll((Collection<? extends SelectCubeMeasure>) Select(
						aDtSelMea, conArray));

				if (oMeaRows.size() == 0) {
					conArray = new ArrayList<Condition>();
					condition = new Condition();
					condition.setCondition(Comparison.Equals);
					condition.setConditionColmn("PARENT_UNI_NM");
					condition.setConditionValue(sMeaGrpNm);
					conArray.add(condition);

					ArrayList<SelectCubeWhere> oWhereRows = (ArrayList<SelectCubeWhere>) Select(
							aDtWhere, conArray);
					sMeaTblNm = oWhereRows.get(0).getTBL_NM();
				} else {
					sMeaTblNm = oMeaRows.get(0).getMEA_TBL_NM();
				}

				oSelClauseColl.clear();
//				oJoinClauseColl.clear();

				sSelClauseScript = "";
				sFromClauseScript = "";
				sGroupByClauseScript = "";
				// ---------------------------------------------------------------------'
				// FROM 절 시작
				// ---------------------------------------------------------------------'
				oQueryGen = new QueryGen();
				oQueryGen.SelectFromTable(sMeaTblNm);
				sFromClauseScript = oQueryGen.BuildQueryFrom();

				// ---------------------------------------------------------------------'
				// FROM 절 종료
				// ---------------------------------------------------------------------'

				ArrayList<TblAlias> oDtTblAlias = new ArrayList<TblAlias>();
				
				//---------------------------------------------------------------------'
                // SELECT 절 시작
                //---------------------------------------------------------------------'
				oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, sMeaGrpNm, oDtTblAlias);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseColl);
				sSelClauseScript = oQueryGen.BuildQuerySelect();
				
				//---------------------------------------------------------------------'
                // SELECT 절 종료
                //---------------------------------------------------------------------'
				
				//---------------------------------------------------------------------'
                // SELECT A.COL_NM 절 시작
                //---------------------------------------------------------------------'
				oSelClauseCollRename = CubeSelClauseForRenameTable(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, sMeaGrpNm, oDtTblAlias);
				
				oQueryGen = new QueryGen();
				
				oQueryGen.SelectColumns(oSelClauseCollRename);
				String sSelCaluseScriptForRename = oQueryGen.BuildQuerySelectDistinct();
				//---------------------------------------------------------------------'
                // SELECT A.COL_NM 절 종료
                //---------------------------------------------------------------------'
				
                //---------------------------------------------------------------------'
                // GROUP BY 절 시작
                //---------------------------------------------------------------------'
				
				oQueryGen = new QueryGen();
				/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
				ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,oDtTblAlias, aDtSel, aDtSelMea);
				
				if(oGroupByColl.size() > 0)
				{
					oQueryGen.GroupBy(oGroupByColl);
					sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
				}
				
				//---------------------------------------------------------------------'
                // GROUP BY 절 종료
                //---------------------------------------------------------------------'
				sQuery = sSelCaluseScriptForRename + vbCrLf + " FROM (";
				sQuery = sQuery + vbCrLf + sSelClauseScript;
				sQuery = sQuery + vbCrLf + sFromClauseScript;
            	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
            	sQuery = sQuery + vbCrLf + " ) A";
			}
		}//MeaGroup
		else
		{
//			/*'---------------------------------------------------------------------'
//            ' SELECT 절 시작
//            '---------------------------------------------------------------------'*/
//			
			oSelClauseColl = CubeSelClause(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, "", new ArrayList<TblAlias> ());
			
			oQueryGen = new QueryGen();
			
			oQueryGen.SelectColumns(oSelClauseColl);
			sSelClauseScript = oQueryGen.BuildQuerySelect();
//			
//			/*'---------------------------------------------------------------------'
//            ' SELECT 절 종료
//            '---------------------------------------------------------------------'*/
//			
			//---------------------------------------------------------------------'
            // SELECT A.COL_NM 절 시작
            //---------------------------------------------------------------------'
			oSelClauseCollRename = CubeSelClauseForRenameTable(aDBMSType, aDtSel, aDtSelHIe, aDtSelMea, "", new ArrayList<TblAlias> ());
			
			oQueryGen = new QueryGen();
			
			oQueryGen.SelectColumns(oSelClauseCollRename);
			String sSelCaluseScriptForRename = oQueryGen.BuildQuerySelectDistinct();
			//---------------------------------------------------------------------'
            // SELECT A.COL_NM 절 종료
            //---------------------------------------------------------------------'
			
//			/*'---------------------------------------------------------------------'
//            ' JOIN 절 시작
//            '---------------------------------------------------------------------'*/
//			
			ArrayList<Hierarchy> oDtSelHieCopy = aDtSelHIe;
			ArrayList<SelectCubeMeasure> oDtSelMeaCopy = aDtSelMea;
			ArrayList<SelectCubeWhere> oDtWhereCopy = aDtWhere;
			ArrayList<SelectCubeOrder> oDtOrderCopy = aDtOrder;
			ArrayList<Relation> oDtJoin = CubeJoinSetting(oDtSelHieCopy, oDtSelMeaCopy, oDtWhereCopy, oDtOrderCopy, aDtCubeRel, aDtDsViewRel, true);
//			
//			
//			/* '---------------------------------------------------------------------'
//            ' FROM 절 시작
//            '---------------------------------------------------------------------'*/
//			
			String sFromTblNm = FromTblNm(oDtJoin);
			
			oQueryGen.SelectFromTable(sFromTblNm);
			sFromClauseScript = oQueryGen.BuildQueryFrom();
//			
//			/* '---------------------------------------------------------------------'
//            ' FROM 절 종료
//            '---------------------------------------------------------------------'*/
//			
//            //---------------------------------------------------------------------'
//            // GROUP BY 절 시작
//            //---------------------------------------------------------------------'
//			
			oQueryGen = new QueryGen();
			/*dogfoot 주제영역 계산식없는 측정값 그룹BY 오류 수정 shlim 20210124*/
			ArrayList<String> oGroupByColl = CubeGroupByByClause(aDBMSType,aDtSelHIe,new ArrayList<TblAlias> (), aDtSel, aDtSelMea);
			
			if(oGroupByColl.size() > 0)
			{
				oQueryGen.GroupBy(oGroupByColl);
				sGroupByClauseScript = oQueryGen.BuildQueryGroupBy();
			}
//			
//			//---------------------------------------------------------------------'
//            // GROUP BY 절 종료
//            //---------------------------------------------------------------------'
//			
			sQuery = sSelCaluseScriptForRename +  vbCrLf + " FROM (";
			sQuery = sQuery + vbCrLf + sSelClauseScript;
			sQuery = sQuery + vbCrLf + sFromClauseScript;
        	sQuery = sQuery + vbCrLf + sGroupByClauseScript;
        	sQuery = sQuery + vbCrLf + " ) A";
		}
		
		 if(bNonRelQuery)
		 {
			 System.out.println("REL ERROR" + vbCrLf + sQuery);
			 return "REL ERROR";
		 }
		 else
			 return sQuery;
	}
}
