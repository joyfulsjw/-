# -*- coding: UTF-8 -*-
import idc
import idaapi
import idautils
import ida_dbg
import sys
import os
import collections
import ida_name
import ida_typeinf
import ida_dbg
import ida_idaapi
import ida_idd
import ida_kernwin
import ida_typeinf
import ida_name
from idaapi import *

class MyDbgHook(DBG_Hooks):
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        print("Process started, pid=%d tid=%d name=%s" % (pid, tid, name))
        idc.add_bpt(ida_ida.inf_get_min_ea(), 0, BPT_ENABLED | BPT_UPDMEM)
        tib_segm_name = ("TIB[%08X]" % getn_thread(0))
        tib_segm = get_segm_by_name(tib_segm_name)
        wow_peb64 = tib_segm.start_ea
        
        patch_dbg_byte(wow_peb64 + 2, 0)
        peb = wow_peb64 + 0x1000
        patch_dbg_byte(peb + 2, 0)
        peb_process_parameters = idaapi.get_dword(peb + 0x10)
        flag = idaapi.get_dword(peb_process_parameters + 0x8)
        patch_dword(peb_process_parameters + 0x8, flag | 0x4000)
        peb64_process_parameters = idaapi.get_qword(wow_peb64 + 0x20)
        flag = idaapi.get_dword(peb64_process_parameters + 0x8)
        patch_dword(peb64_process_parameters + 0x8, flag | 0x4000)


    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        print("Process attach pid=%d tid=%d ea=0x%x name=%s base=%x size=%x" % (pid, tid, ea, name, base, size))
        tib_segm_name = ("TIB[%08X]" % getn_thread(0))
        tib_segm = get_segm_by_name(tib_segm_name)
        wow_peb64 = tib_segm.start_ea
        
        patch_dbg_byte(wow_peb64 + 2, 0)
        peb = wow_peb64 + 0x1000
        patch_dbg_byte(peb + 2, 0)
        peb_process_parameters = idaapi.get_dword(peb + 0x10)
        flag = idaapi.get_dword(peb_process_parameters + 0x8)
        patch_dword(peb_process_parameters + 0x8, flag | 0x4000)
        peb64_process_parameters = idaapi.get_qword(wow_peb64 + 0x20)
        flag = idaapi.get_dword(peb64_process_parameters + 0x8)
        patch_dword(peb64_process_parameters + 0x8, flag | 0x4000)



# Remove an existing debug hook
try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass
print(sys.version)
# Install the debug hook
debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0

# set_debugger_options(0x1000)
# start_process()