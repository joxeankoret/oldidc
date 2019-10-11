"""
IDA Python's idc.py <= 7.3 compatibility module
Author: Joxean Koret

Public Domain
"""

import idc
import ida_ua
import ida_ida
import ida_idp
import ida_dbg
import ida_pro
import ida_name
import ida_xref
import ida_auto
import ida_nalt
import ida_name
import ida_enum
import ida_lines
import ida_fixup
import ida_frame
import ida_funcs
import ida_bytes
import ida_loader
import ida_search
import ida_struct
import ida_segment
import ida_kernwin

from idc import *

GetString = ida_bytes.get_strlit_contents
GetRegValue = idc.get_reg_value
LocByName = idc.get_name_ea_simple
AddBpt = idc.add_bpt

def Compile(file): return idc.CompileEx(file, 1)

def OpOffset(ea, base): return idc.op_plain_offset(ea, -1, base)

def OpNum(ea): return idc.op_num(ea, -1)

def OpChar(ea): return idc.op_chr(ea, -1)

def OpSegment(ea): return idc.op_seg(ea, -1)

def OpDec(ea): return idc.op_dec(ea, -1)

def OpAlt1(ea, str): return idc.op_man(ea, 0, str)

def OpAlt2(ea, str): return idc.op_man(ea, 1, str)

def StringStp(x): return idc.set_inf_attr(INF_STRLIT_BREAK, x)

def LowVoids(x): return idc.set_inf_attr(INF_LOW_OFF, x)

def HighVoids(x): return idc.set_inf_attr(INF_HIGH_OFF, x)

def TailDepth(x): return idc.set_inf_attr(INF_MAXREF, x)

def Analysis(x): return idc.set_flag(INF_GENFLAGS, INFFL_AUTO, x)

def Comments(x): return idc.set_flag(INF_CMTFLAG, SW_ALLCMT, x)

def Voids(x): return idc.set_flag(INF_OUTFLAGS, OFLG_SHOW_VOID, x)

def XrefShow(x): return idc.set_inf_attr(INF_XREFNUM, x)

def Indent(x): return idc.set_inf_attr(INF_INDENT, x)

def CmtIndent(x): return idc.set_inf_attr(INF_COMMENT, x)

def AutoShow(x): return idc.set_flag(INF_OUTFLAGS, OFLG_SHOW_AUTO, x)

def MinEA(): return idc.get_inf_attr(INF_MIN_EA)

def MaxEA(): return idc.get_inf_attr(INF_MAX_EA)

def StartEA(): return idc.get_inf_attr(INF_START_EA)

def set_start_cs(x): return idc.set_inf_attr(INF_START_CS, x)

def set_start_ip(x): return idc.set_inf_attr(INF_START_IP, x)

def auto_make_code(x): return idc.auto_mark_range(x, (x)+1, AU_CODE);

def AddConst(enum_id, name, value): return idc.add_enum_member(enum_id, name, value, -1)

def AddStruc(index, name): return idc.add_struc(index, name, 0)

def AddUnion(index, name): return idc.add_struc(index, name, 1)

def OpStroff(ea, n, strid): return idc.op_stroff(ea, n, strid, 0)

def OpEnum(ea, n, enumid): return idc.op_enum(ea, n, enumid, 0)

def DelConst(id, v, mask): return idc.del_enum_member(id, v, 0, mask)

def GetConst(id, v, mask): return idc.get_enum_member(id, v, 0, mask)

AnalyseRange = idc.plan_and_wait
AnalyseArea = idc.plan_and_wait
AnalyzeArea = idc.plan_and_wait

def MakeStruct(ea, name): return idc.create_struct(ea, -1, name)

def Name(ea): return idc.get_name(ea, ida_name.GN_VISIBLE)

GetTrueName = ida_name.get_ea_name

def MakeName(ea, name): return idc.set_name(ea, name, SN_CHECK)

def GetFrame(ea): return idc.get_func_attr(ea, FUNCATTR_FRAME)

def GetFrameLvarSize(ea): return idc.get_func_attr(ea, FUNCATTR_FRSIZE)

def GetFrameRegsSize(ea): return idc.get_func_attr(ea, FUNCATTR_FRREGS)

def GetFrameArgsSize(ea): return idc.get_func_attr(ea, FUNCATTR_ARGSIZE)

def GetFunctionFlags(ea): return idc.get_func_attr(ea, FUNCATTR_FLAGS)

def SetFunctionFlags(ea, flags): return idc.set_func_attr(ea, FUNCATTR_FLAGS, flags)

SegCreate = idc.AddSeg
SegDelete = idc.del_segm
SegBounds = idc.set_segment_bounds
SegRename = idc.set_segm_name
SegClass = idc.set_segm_class
SegAddrng = idc.set_segm_addressing
SegDefReg = idc.set_default_sreg_value

def Comment(ea): return idc.get_cmt(ea, 0)

def RptCmt(ea): return idc.get_cmt(ea, 1)

def MakeByte(ea): return ida_bytes.create_data(ea, FF_BYTE, 1, ida_idaapi.BADADDR)

def MakeWord(ea): return ida_bytes.create_data(ea, FF_WORD, 2, ida_idaapi.BADADDR)

def MakeDword(ea): return ida_bytes.create_data(ea, FF_DWORD, 4, ida_idaapi.BADADDR)

def MakeQword(ea): return ida_bytes.create_data(ea, FF_QWORD, 8, ida_idaapi.BADADDR)

def MakeOword(ea): return ida_bytes.create_data(ea, FF_OWORD, 16, ida_idaapi.BADADDR)

def MakeYword(ea): return ida_bytes.create_data(ea, FF_YWORD, 32, ida_idaapi.BADADDR)

def MakeFloat(ea): return ida_bytes.create_data(ea, FF_FLOAT, 4, ida_idaapi.BADADDR)

def MakeDouble(ea): return ida_bytes.create_data(ea, FF_DOUBLE, 8, ida_idaapi.BADADDR)

def MakePackReal(ea): return ida_bytes.create_data(ea, FF_PACKREAL, 10, ida_idaapi.BADADDR)

def MakeTbyte(ea): return ida_bytes.create_data(ea, FF_TBYTE, 10, ida_idaapi.BADADDR)

def MakeCustomData(ea, size, dtid, fid): return ida_bytes.create_data(ea, FF_CUSTOM, size, dtid|((fid)<<16))

def SetReg(ea, reg, value): return idc.split_sreg_range(ea, reg, value, SR_user)

SegByName = idc.selector_by_name
MK_FP = idc.to_ea
toEA = idc.to_ea
MakeCode = idc.create_insn
MakeNameEx = idc.set_name
MakeArray = idc.make_array
MakeData = ida_bytes.create_data
GetRegValue = idc.get_reg_value
SetRegValue = idc.set_reg_value
Byte = idc.get_wide_byte
Word = idc.get_wide_word
Dword = idc.get_wide_dword
Qword = idc.get_qword
LocByName = idc.get_name_ea_simple
ScreenEA = idc.get_screen_ea
GetTinfo = idc.get_tinfo
OpChr = idc.op_chr
OpSeg = idc.op_seg
OpNumber = idc.op_num
OpDecimal = idc.op_dec
OpOctal = idc.op_oct
OpBinary = idc.op_bin
OpHex = idc.op_hex
OpAlt = idc.op_man
OpSign = idc.toggle_sign
OpNot = idc.toggle_bnot
OpEnumEx = idc.op_enum
OpStroffEx = idc.op_stroff
OpStkvar = idc.op_stkvar
OpFloat = idc.op_flt
OpOffEx = idc.op_offset
OpOff = idc.op_plain_offset
MakeStructEx = idc.create_struct
Jump = ida_kernwin.jumpto
GenerateFile = idc.gen_file
GenFuncGdl = idc.gen_flow_graph
GenCallGdl = idc.gen_simple_call_chart
IdbByte = ida_bytes.get_db_byte
DbgByte = idc.read_dbg_byte
DbgWord = idc.read_dbg_word
DbgDword = idc.read_dbg_dword
DbgQword = idc.read_dbg_qword
DbgRead = idc.read_dbg_memory
DbgWrite = idc.write_dbg_memory
PatchDbgByte = idc.patch_dbg_byte
PatchByte = ida_bytes.patch_byte
PatchWord = ida_bytes.patch_word
PatchDword = ida_bytes.patch_dword
PatchQword = ida_bytes.patch_qword
SetProcessorType = ida_idp.set_processor_type
SetTargetAssembler = ida_idp.set_target_assembler
Batch = idc.batch
SetSegDefReg = idc.set_default_sreg_value
GetReg = idc.get_sreg
SetRegEx = idc.split_sreg_range

def AskStr(defval, prompt): return ida_kernwin.ask_str(defval, 0, prompt)

AskFile = ida_kernwin.ask_file
AskAddr = ida_kernwin.ask_addr
AskLong = ida_kernwin.ask_long
AskSeg = ida_kernwin.ask_seg

def AskIdent(defval, prompt): return ida_kernwin.ask_str(defval, ida_kernwin.HIST_IDENT, prompt)

AskYN = ida_kernwin.ask_yn
DeleteAll = idc.delete_all_segments
AddSegEx = idc.add_segm_ex
SetSegBounds = idc.set_segment_bounds
RenameSeg = idc.set_segm_name
SetSegClass = idc.set_segm_class
SetSegAddressing = idc.set_segm_addressing
SetSegmentAttr = idc.set_segm_attr
GetSegmentAttr = idc.get_segm_attr
SetStorageType = ida_bytes.change_storage_type
MoveSegm = idc.move_segm
RebaseProgram = ida_segment.rebase_program
LocByNameEx = ida_name.get_name_ea
SegByBase = idc.get_segm_by_sel
GetCurrentLine = idc.get_curline
SelStart = idc.read_selection_start
SelEnd = idc.read_selection_end
FirstSeg = idc.get_first_seg
NextSeg = idc.get_next_seg
SegName = idc.get_segm_name
CommentEx = ida_bytes.get_cmt
AltOp = ida_bytes.get_forced_operand
GetDisasmEx = idc.generate_disasm_line
GetMnem = idc.print_insn_mnem
GetOpType = idc.get_operand_type
GetOperandValue = idc.get_operand_value
DecodeInstruction = ida_ua.decode_insn
NextAddr = ida_bytes.next_addr
PrevAddr = ida_bytes.prev_addr
NextNotTail = ida_bytes.next_not_tail
PrevNotTail = ida_bytes.prev_not_tail
ItemHead = ida_bytes.get_item_head
ItemEnd = ida_bytes.get_item_end
ItemSize = idc.get_item_size
AnalyzeRange = idc.plan_and_wait
Eval = idc.eval_idc
Exit = ida_pro.qexit
FindVoid = ida_search.find_suspop
FindCode = ida_search.find_code
FindData = ida_search.find_data
FindUnexplored = ida_search.find_unknown
FindExplored = ida_search.find_defined
FindImmediate = ida_search.find_imm
AddCodeXref = ida_xref.add_cref
DelCodeXref = ida_xref.del_cref
Rfirst = ida_xref.get_first_cref_from
RfirstB = ida_xref.get_first_cref_to
Rnext = ida_xref.get_next_cref_from
RnextB = ida_xref.get_next_cref_to
Rfirst0 = ida_xref.get_first_fcref_from
RfirstB0 = ida_xref.get_first_fcref_to
Rnext0 = ida_xref.get_next_fcref_from
RnextB0 = ida_xref.get_next_fcref_to
Dfirst = ida_xref.get_first_dref_from
Dnext = ida_xref.get_next_dref_from
DfirstB = ida_xref.get_first_dref_to
DnextB = ida_xref.get_next_dref_to
XrefType = idc.get_xref_type
AutoUnmark = ida_auto.auto_unmark
AutoMark2 = ida_auto.auto_mark_range
SetSelector = ida_segment.set_selector
AskSelector = idc.sel2para
ask_selector = idc.sel2para
FindSelector = idc.find_selector
DelSelector = ida_segment.del_selector
MakeFunction = ida_funcs.add_func
DelFunction = ida_funcs.del_func
SetFunctionEnd = ida_funcs.set_func_end
NextFunction = idc.get_next_func
PrevFunction = idc.get_prev_func
GetFunctionAttr = idc.get_func_attr
SetFunctionAttr = idc.set_func_attr
GetFunctionName = idc.get_func_name
GetFunctionCmt = idc.get_func_cmt
SetFunctionCmt = idc.set_func_cmt
ChooseFunction = idc.choose_func
GetFuncOffset = idc.get_func_off_str
MakeLocal = idc.define_local_var
FindFuncEnd = idc.find_func_end
GetFrameSize = idc.get_frame_size
MakeFrame = idc.set_frame_size
GetSpd = idc.get_spd
GetSpDiff = idc.get_sp_delta
DelStkPnt = idc.del_stkpnt
AddAutoStkPnt2 = idc.add_auto_stkpnt
RecalcSpd = ida_frame.recalc_spd
GetMinSpd = idc.get_min_spd_ea
GetFchunkAttr = idc.get_fchunk_attr
SetFchunkAttr = idc.set_fchunk_attr
GetFchunkReferer = ida_funcs.get_fchunk_referer
NextFchunk = idc.get_next_fchunk
PrevFchunk = idc.get_prev_fchunk
AppendFchunk = idc.append_func_tail
RemoveFchunk = idc.remove_fchunk
SetFchunkOwner = idc.set_tail_owner
FirstFuncFchunk = idc.first_func_chunk
NextFuncFchunk = idc.next_func_chunk
GetEntryPointQty = ida_entry.get_entry_qty
AddEntryPoint = ida_entry.add_entry
GetEntryName = ida_entry.get_entry_name
GetEntryOrdinal = ida_entry.get_entry_ordinal
GetEntryPoint = ida_entry.get_entry
RenameEntryPoint = ida_entry.rename_entry
GetNextFixupEA = ida_fixup.get_next_fixup_ea
GetPrevFixupEA = ida_fixup.get_prev_fixup_ea
GetFixupTgtType = idc.get_fixup_target_type
GetFixupTgtFlags = idc.get_fixup_target_flags
GetFixupTgtSel = idc.get_fixup_target_sel
GetFixupTgtOff = idc.get_fixup_target_off
GetFixupTgtDispl = idc.get_fixup_target_dis
SetFixup = idc.set_fixup
DelFixup = ida_fixup.del_fixup
MarkPosition = idc.put_bookmark
GetMarkedPos = idc.get_bookmark
GetMarkComment = idc.get_bookmark_desc
GetStrucQty = ida_struct.get_struc_qty
GetFirstStrucIdx = ida_struct.get_first_struc_idx
GetLastStrucIdx = ida_struct.get_last_struc_idx
GetNextStrucIdx = ida_struct.get_next_struc_idx
GetPrevStrucIdx = ida_struct.get_prev_struc_idx
GetStrucIdx = ida_struct.get_struc_idx
GetStrucId = ida_struct.get_struc_by_idx
GetStrucIdByName = ida_struct.get_struc_id
GetStrucName = ida_struct.get_struc_name
GetStrucComment = ida_struct.get_struc_cmt
GetStrucSize = ida_struct.get_struc_size
GetMemberQty = idc.get_member_qty
GetStrucPrevOff = idc.get_prev_offset
GetStrucNextOff = idc.get_next_offset
GetFirstMember = idc.get_first_member
GetLastMember = idc.get_last_member
GetMemberOffset = idc.get_member_offset
GetMemberName = idc.get_member_name
GetMemberComment = idc.get_member_cmt
GetMemberSize = idc.get_member_size
GetMemberFlag = idc.get_member_flag
GetMemberStrId = idc.get_member_strid
GetMemberId = idc.get_member_id
AddStrucEx = idc.add_struc
IsUnion = idc.is_union
DelStruc = idc.del_struc
SetStrucIdx = idc.set_struc_idx
SetStrucName = ida_struct.set_struc_name
SetStrucComment = ida_struct.set_struc_cmt
AddStrucMember = idc.add_struc_member
DelStrucMember = idc.del_struc_member
SetMemberName = idc.set_member_name
SetMemberType = idc.set_member_type
SetMemberComment = idc.set_member_cmt
ExpandStruc = idc.expand_struc
SetLineNumber = ida_nalt.set_source_linnum
GetLineNumber = ida_nalt.get_source_linnum
DelLineNumber = ida_nalt.del_source_linnum
AddSourceFile = ida_lines.add_sourcefile
GetSourceFile = ida_lines.get_sourcefile
DelSourceFile = ida_lines.del_sourcefile
CreateArray = idc.create_array
GetArrayId = idc.get_array_id
RenameArray = idc.rename_array
DeleteArray = idc.delete_array
SetArrayLong = idc.set_array_long
SetArrayString = idc.set_array_string
GetArrayElement = idc.get_array_element
DelArrayElement = idc.del_array_element
GetFirstIndex = idc.get_first_index
GetNextIndex = idc.get_next_index
GetLastIndex = idc.get_last_index
GetPrevIndex = idc.get_prev_index
SetHashLong = idc.set_hash_long
SetHashString = idc.set_hash_string
GetHashLong = idc.get_hash_long
GetHashString = idc.get_hash_string
DelHashElement = idc.del_hash_string
GetFirstHashKey = idc.get_first_hash_key
GetNextHashKey = idc.get_next_hash_key
GetLastHashKey = idc.get_last_hash_key
GetPrevHashKey = idc.get_prev_hash_key
GetEnumQty = ida_enum.get_enum_qty
GetnEnum = ida_enum.getn_enum
GetEnumIdx = ida_enum.get_enum_idx
GetEnum = ida_enum.get_enum
GetEnumName = ida_enum.get_enum_name
GetEnumCmt = ida_enum.get_enum_cmt
GetEnumSize = ida_enum.get_enum_size
GetEnumWidth = ida_enum.get_enum_width
GetEnumFlag = ida_enum.get_enum_flag
GetConstByName = ida_enum.get_enum_member_by_name
GetConstValue = ida_enum.get_enum_member_value
GetConstBmask = ida_enum.get_enum_member_bmask
GetConstEnum = ida_enum.get_enum_member_enum
GetConstEx = idc.get_enum_member
GetFirstBmask = ida_enum.get_first_bmask
GetLastBmask = ida_enum.get_last_bmask
GetNextBmask = ida_enum.get_next_bmask
GetPrevBmask = ida_enum.get_prev_bmask
GetFirstConst = idc.get_first_enum_member
GetLastConst = idc.get_last_enum_member
GetNextConst = idc.get_next_enum_member
GetPrevConst = idc.get_prev_enum_member
GetConstName = idc.get_enum_member_name
GetConstCmt = idc.get_enum_member_cmt
AddEnum = idc.add_enum
DelEnum = ida_enum.del_enum
SetEnumIdx = ida_enum.set_enum_idx
SetEnumName = ida_enum.set_enum_name
SetEnumCmt = ida_enum.set_enum_cmt
SetEnumFlag = ida_enum.set_enum_flag
SetEnumWidth = ida_enum.set_enum_width
SetEnumBf = ida_enum.set_enum_bf
AddConstEx = idc.add_enum_member
DelConstEx = idc.del_enum_member
SetConstName = ida_enum.set_enum_member_name
SetConstCmt = ida_enum.set_enum_member_cmt
IsBitfield = ida_enum.is_bf
SetBmaskName = idc.set_bmask_name
GetBmaskName = idc.get_bmask_name
SetBmaskCmt = idc.set_bmask_cmt
GetBmaskCmt = idc.get_bmask_cmt
GetLongPrm = idc.get_inf_attr
GetShortPrm = idc.get_inf_attr
GetCharPrm = idc.get_inf_attr
SetLongPrm = idc.set_inf_attr
SetShortPrm = idc.set_inf_attr
SetCharPrm = idc.set_inf_attr
ChangeConfig = idc.process_config_line
AddHotkey = ida_kernwin.add_idc_hotkey
DelHotkey = ida_kernwin.del_idc_hotkey
GetInputFile = ida_nalt.get_root_filename
GetInputFilePath = ida_nalt.get_input_file_path
SetInputFilePath = ida_nalt.set_root_filename
Exec = idc.call_system
Sleep = idc.qsleep
GetIdaDirectory = idc.idadir
GetIdbPath = idc.get_idb_path
GetInputMD5 = ida_nalt.retrieve_input_file_md5
OpHigh = idc.op_offset_high16
MakeAlign = ida_bytes.create_align
Demangle = idc.demangle_name
SetManualInsn = ida_bytes.set_manual_insn
GetManualInsn = ida_bytes.get_manual_insn
SetArrayFormat = idc.set_array_params
LoadTil = idc.add_default_til
Til2Idb = idc.import_type
GetMaxLocalType = idc.get_ordinal_qty
SetLocalType = idc.set_local_type
GetLocalTinfo = idc.get_local_tinfo
GetLocalTypeName = idc.get_numbered_type_name
PrintLocalTypes = idc.print_decls
SetStatus = ida_auto.set_ida_state
Refresh = ida_kernwin.refresh_idaview_anyway
RefreshLists = ida_kernwin.refresh_choosers
RunPlugin = ida_loader.load_and_run_plugin
ApplySig = ida_funcs.plan_to_apply_idasgn
GetStringType = idc.get_str_type
GetOriginalByte = ida_bytes.get_original_byte
HideRange = ida_bytes.add_hidden_range
SetHiddenRange = idc.update_hidden_range
DelHiddenRange = ida_bytes.del_hidden_range
GetType = idc.get_type
GuessType = idc.guess_type
ParseType = idc.parse_decl
GetColor = idc.get_color
SetColor = idc.set_color
GetBptQty = ida_dbg.get_bpt_qty
GetBptEA = idc.get_bpt_ea
GetBptAttr = idc.get_bpt_attr
SetBptAttr = idc.set_bpt_attr
SetBptCndEx = idc.set_bpt_cond
SetBptCnd = idc.set_bpt_cond
AddBptEx = ida_dbg.add_bpt
AddBpt = ida_dbg.add_bpt
DelBpt = ida_dbg.del_bpt
EnableBpt = ida_dbg.enable_bpt
CheckBpt = ida_dbg.check_bpt
LoadDebugger = ida_dbg.load_debugger
StartDebugger = ida_dbg.start_process
StopDebugger = ida_dbg.exit_process
PauseProcess = ida_dbg.suspend_process

def GetProcessQty(): return ida_dbg.get_processes().size

def GetProcessPid(idx): return ida_dbg.get_processes()[idx].pid

def GetProcessName(idx): return ida_dbg.get_processes()[idx].name

AttachProcess = ida_dbg.attach_process
DetachProcess = ida_dbg.detach_process
GetThreadQty = ida_dbg.get_thread_qty
GetThreadId = ida_dbg.getn_thread
GetCurrentThreadId = ida_dbg.get_current_thread
SelectThread = ida_dbg.select_thread
SuspendThread = ida_dbg.suspend_thread
ResumeThread = ida_dbg.resume_thread
GetFirstModule = idc.get_first_module
GetNextModule = idc.get_next_module
GetModuleName = idc.get_module_name
GetModuleSize = idc.get_module_size
StepInto = ida_dbg.step_into
StepOver = ida_dbg.step_over
RunTo = ida_dbg.run_to
StepUntilRet = ida_dbg.step_until_ret
GetDebuggerEvent = ida_dbg.wait_for_next_event
GetProcessState = ida_dbg.get_process_state
SetDebuggerOptions = ida_dbg.set_debugger_options
SetRemoteDebugger = ida_dbg.set_remote_debugger
GetDebuggerEventCondition = ida_dbg.get_debugger_event_cond
SetDebuggerEventCondition = ida_dbg.set_debugger_event_cond
GetEventId = idc.get_event_id
GetEventPid = idc.get_event_pid
GetEventTid = idc.get_event_tid
GetEventEa = idc.get_event_ea
IsEventHandled = idc.is_event_handled
GetEventModuleName = idc.get_event_module_name
GetEventModuleBase = idc.get_event_module_base
GetEventModuleSize = idc.get_event_module_size
GetEventExitCode = idc.get_event_exit_code
GetEventInfo = idc.get_event_info
GetEventBptHardwareEa = idc.get_event_bpt_hea
GetEventExceptionCode = idc.get_event_exc_code
GetEventExceptionEa = idc.get_event_exc_ea
GetEventExceptionInfo = idc.get_event_exc_info
CanExceptionContinue = idc.can_exc_continue
RefreshDebuggerMemory = ida_dbg.refresh_debugger_memory
TakeMemorySnapshot = ida_segment.take_memory_snapshot
EnableTracing = idc.enable_tracing
GetStepTraceOptions = ida_dbg.get_step_trace_options
SetStepTraceOptions = ida_dbg.set_step_trace_options
DefineException = ida_dbg.define_exception
BeginTypeUpdating = ida_typeinf.begin_type_updating
EndTypeUpdating = ida_typeinf.end_type_updating
ValidateNames = idc.validate_idb_names

def SegAlign(ea, alignment): return idc.set_segm_attr(ea, SEGATTR_ALIGN, alignment)

def SegComb(ea, comb): return idc.set_segm_attr(ea, SEGATTR_COMB, comb)

def MakeComm(ea, cmt): return idc.set_cmt(ea, cmt, 0)

def MakeRptCmt(ea, cmt): return idc.set_cmt(ea, cmt, 1)

MakeUnkn = ida_bytes.del_items
MakeUnknown = ida_bytes.del_items

def LineA(ea, n): return ida_lines.get_extra_cmt(ea, E_PREV + (n))

def LineB(ea, n): return ida_lines.get_extra_cmt(ea, E_NEXT + (n))

def ExtLinA(ea, n, line): return ida_lines.update_extra_cmt(ea, E_PREV + (n), line)

def ExtLinB(ea, n, line): return ida_lines.update_extra_cmt(ea, E_NEXT + (n), line)

def DelExtLnA(ea, n): return ida_lines.del_extra_cmt(ea, E_PREV + (n))

def DelExtLnB(ea, n): return ida_lines.del_extra_cmt(ea, E_NEXT + (n))

SetSpDiff = ida_frame.add_user_stkpnt
AddUserStkPnt = ida_frame.add_user_stkpnt

def NameEx(From, ea): return idc.get_name(ea, ida_name.GN_VISIBLE | calc_gtn_flags(From, ea))

def GetTrueNameEx(From, ea): return idc.get_name(ea, calc_gtn_flags(From, ea))

Message = ida_kernwin.msg
UMessage = ida_kernwin.msg
DelSeg = ida_segment.del_segm
Wait = ida_auto.auto_wait
LoadTraceFile = ida_dbg.load_trace_file
SaveTraceFile = ida_dbg.save_trace_file
CheckTraceFile = ida_dbg.is_valid_trace_file
DiffTraceFile = ida_dbg.diff_trace_file
SetTraceDesc = ida_dbg.get_trace_file_desc
GetTraceDesc = ida_dbg.set_trace_file_desc
GetMaxTev = ida_dbg.get_tev_qty
GetTevEa = ida_dbg.get_tev_ea
GetTevType = ida_dbg.get_tev_type
GetTevTid = ida_dbg.get_tev_tid
GetTevCallee = ida_dbg.get_call_tev_callee
GetTevReturn = ida_dbg.get_ret_tev_return
GetBptTevEa = ida_dbg.get_bpt_tev_ea
ArmForceBLJump = idc.force_bl_jump
ArmForceBLCall = idc.force_bl_call
BochsCommand = idc.send_dbg_command
SendGDBMonitor = idc.send_dbg_command
WinDbgCommand = idc.send_dbg_command

def SetAppcallOptions(x): return idc.set_inf_attr(INF_APPCALL_OPTIONS, x)

def GetAppcallOptions(): return idc.get_inf_attr(INF_APPCALL_OPTIONS)

AF2_ANORET = ida_ida.AF_ANORET
AF2_CHKUNI = ida_ida.AF_CHKUNI
AF2_DATOFF = ida_ida.AF_DATOFF
AF2_DOCODE = ida_ida.AF_DOCODE
AF2_DODATA = ida_ida.AF_DODATA
AF2_FTAIL = ida_ida.AF_FTAIL
AF2_HFLIRT = ida_ida.AF_HFLIRT
AF2_JUMPTBL = ida_ida.AF_JUMPTBL
AF2_PURDAT = ida_ida.AF_PURDAT
AF2_REGARG = ida_ida.AF_REGARG
AF2_SIGCMT = ida_ida.AF_SIGCMT
AF2_SIGMLT = ida_ida.AF_SIGMLT
AF2_STKARG = ida_ida.AF_STKARG
AF2_TRFUNC = ida_ida.AF_TRFUNC
AF2_VERSP = ida_ida.AF_VERSP
AF_ASCII = ida_ida.AF_STRLIT
ASCF_AUTO = ida_ida.STRF_AUTO
ASCF_COMMENT = ida_ida.STRF_COMMENT
ASCF_GEN = ida_ida.STRF_GEN
ASCF_SAVECASE = ida_ida.STRF_SAVECASE
ASCF_SERIAL = ida_ida.STRF_SERIAL
ASCSTR_C = ida_nalt.STRTYPE_C
ASCSTR_LEN2 = ida_nalt.STRTYPE_LEN2
ASCSTR_LEN4 = ida_nalt.STRTYPE_LEN4
ASCSTR_PASCAL = ida_nalt.STRTYPE_PASCAL
ASCSTR_TERMCHR = ida_nalt.STRTYPE_TERMCHR
ASCSTR_ULEN2 = ida_nalt.STRTYPE_LEN2_16
ASCSTR_ULEN4 = ida_nalt.STRTYPE_LEN4_16
ASCSTR_UNICODE = ida_nalt.STRTYPE_C_16
DOUNK_SIMPLE = ida_bytes.DELIT_SIMPLE
DOUNK_EXPAND = ida_bytes.DELIT_EXPAND
DOUNK_DELNAMES = ida_bytes.DELIT_DELNAMES
FF_ASCI = ida_bytes.FF_STRLIT
FF_DWRD = ida_bytes.FF_DWORD
FF_OWRD = ida_bytes.FF_OWORD
FF_QWRD = ida_bytes.FF_QWORD
FF_STRU = ida_bytes.FF_STRUCT
FF_TBYT = ida_bytes.FF_TBYTE
FIXUP_BYTE = ida_fixup.FIXUP_OFF8
FIXUP_CREATED = ida_fixup.FIXUPF_CREATED
FIXUP_EXTDEF = ida_fixup.FIXUPF_EXTDEF
FIXUP_REL = ida_fixup.FIXUPF_REL
FIXUP_UNUSED = ida_fixup.FIXUPF_UNUSED
GetFlags = ida_bytes.get_full_flags
ResumeProcess = idc.resume_process
isEnabled = ida_bytes.is_mapped
hasValue = ida_bytes.has_value
isByte = ida_bytes.is_byte
isWord = ida_bytes.is_word
isDwrd = ida_bytes.is_dword
isQwrd = ida_bytes.is_qword
isOwrd = ida_bytes.is_oword
isTbyt = ida_bytes.is_tbyte
isFloat = ida_bytes.is_float
isDouble = ida_bytes.is_double
isASCII = ida_bytes.is_strlit
isStruct = ida_bytes.is_struct
isAlign = ida_bytes.is_align
isChar0 = ida_bytes.is_char0
isChar1 = ida_bytes.is_char1
isCode = ida_bytes.is_code
isData = ida_bytes.is_data
isDefArg0 = ida_bytes.is_defarg0
isDefArg1 = ida_bytes.is_defarg1
isEnum0 = ida_bytes.is_enum0
isEnum1 = ida_bytes.is_enum1
isFlow = ida_bytes.is_flow
isHead = ida_bytes.is_head
isLoaded = ida_bytes.is_loaded
isOff0 = ida_bytes.is_off0
isOff1 = ida_bytes.is_off1
isPackReal = ida_bytes.is_pack_real
isSeg0 = ida_bytes.is_seg0
isSeg1 = ida_bytes.is_seg1
isStkvar0 = ida_bytes.is_stkvar0
isStkvar1 = ida_bytes.is_stkvar1
isStroff0 = ida_bytes.is_stroff0
isStroff1 = ida_bytes.is_stroff1
isTail = ida_bytes.is_tail
isUnknown = ida_bytes.is_unknown
SEGDEL_KEEP = ida_segment.SEGMOD_KEEP
SEGDEL_PERM = ida_segment.SEGMOD_KILL
SEGDEL_SILENT = ida_segment.SEGMOD_SILENT
SETPROC_ALL = ida_idp.SETPROC_LOADER_NON_FATAL
SETPROC_COMPAT = ida_idp.SETPROC_IDB
SETPROC_FATAL = ida_idp.SETPROC_LOADER
INF_CHANGE_COUNTER = idc.INF_DATABASE_CHANGE_COUNT
INF_LOW_OFF = idc.INF_LOWOFF
INF_HIGH_OFF = idc.INF_HIGHOFF
INF_START_PRIVRANGE = idc.INF_PRIVRANGE_START_EA
INF_END_PRIVRANGE = idc.INF_PRIVRANGE_END_EA
INF_TYPE_XREFS = idc.INF_TYPE_XREFNUM
INF_REFCMTS = idc.INF_REFCMTNUM
INF_XREFS = idc.INF_XREFFLAG
INF_NAMELEN = idc.INF_MAX_AUTONAME_LEN
INF_SHORT_DN = idc.INF_SHORT_DEMNAMES
INF_LONG_DN = idc.INF_LONG_DEMNAMES
INF_CMTFLAG = idc.INF_CMTFLG
INF_BORDER = idc.INF_LIMITER
INF_BINPREF = idc.INF_BIN_PREFIX_SIZE
INF_COMPILER = idc.INF_CC_ID
INF_MODEL = idc.INF_CC_CM
INF_SIZEOF_INT = idc.INF_CC_SIZE_I
INF_SIZEOF_BOOL = idc.INF_CC_SIZE_B
INF_SIZEOF_ENUM = idc.INF_CC_SIZE_E
INF_SIZEOF_ALGN = idc.INF_CC_DEFALIGN
INF_SIZEOF_SHORT = idc.INF_CC_SIZE_S
INF_SIZEOF_LONG = idc.INF_CC_SIZE_L
INF_SIZEOF_LLONG = idc.INF_CC_SIZE_LL
INF_SIZEOF_LDBL = idc.INF_CC_SIZE_LDBL
REF_VHIGH = ida_nalt.V695_REF_VHIGH
REF_VLOW = ida_nalt.V695_REF_VLOW
GetOpnd = idc.print_operand
patch_long = ida_bytes.patch_dword

def python_on(): return ida_loader.load_and_run_plugin("idapython", 3)
