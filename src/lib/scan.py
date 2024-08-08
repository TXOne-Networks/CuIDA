
import viv_utils, sys, vivisect, os, time
from vivisect.impemu.emulator import WorkspaceEmulator, envi, vg_path, v_exc, e_exc

# ref: https://github.com/vivisect/vivisect/blob/d6824f02b520969e83f6ce9ea8b585d8f0f7f317/envi/memory.py#L727
def fuzzReadMemStr(emu, va, maxlen=0xfffffff, wide=False):
    terminator = (b'\0', b'\0\0')[bool(wide)]
    for mva, mmaxva, mmap, mbytes in emu._map_defs:
        if mva <= va < mmaxva:
            mva, msize, mperms, mfname = mmap
            if not mperms & vivisect.envi.MM_READ:
                raise envi.SegmentationViolation(va)
            offset = va - mva

            # now find the end of the string based on either \x00, maxlen, or end of map
            end = mbytes.find(terminator, offset)

            left = end - offset
            if end == -1:
                # couldn't find the NULL byte
                mend = offset + maxlen
                cstr = mbytes[offset:mend]
            else:
                # couldn't find the NULL byte go to the end of the map or maxlen
                mend = offset + (maxlen, left)[left < maxlen]
                cstr = mbytes[offset:mend]
            return cstr

    raise envi.SegmentationViolation(va)

def data_reprsent(emu, val):
    if emu.isValidPointer(val):
        if False: #emu.isExecutable(val):
            return "PTR_BINFUNC"
        else:
            probU = emu.vw.isProbablyUnicode(val) #fuzzReadMemStr(emu, val, wide=True)
            probA = emu.vw.isProbablyString(val) #fuzzReadMemStr(emu, val, wide=False)
            if (not probU) and (not probA): #not tryread_unicode.isascii():
                return ( "MEM_BUFF" )
            else:
                strbuff = fuzzReadMemStr(emu, val, wide=probU) 
                szBuffLenScale = len(strbuff) // (2 if probU else 1) # Assert Unicode String
                if szBuffLenScale <= 32:
                    szBuffLenScale = 0
                elif szBuffLenScale <= 260:
                    szBuffLenScale = 1
                else:
                    szBuffLenScale = len( (hex(szBuffLenScale))[2:] ) + 2
                return ( f"STR_UNICODE_{szBuffLenScale}" if probU else f"STR_ANSI_{szBuffLenScale}" )
    return None


def reprVivTaint(self, taint):
    # ref: https://github.com/vivisect/vivisect/blob/d6824f02b520969e83f6ce9ea8b585d8f0f7f317/vivisect/impemu/emulator.py#L611

    va, ttype, tinfo = taint
    if ttype == 'uninitreg':
        trepr = "FUNC_RET" # self.getRegisterName(tinfo)
    elif ttype == 'import':
        lva,lsize,ltype,linfo = tinfo # 'kernel32.TlsGetValue'
        trepr = "FUNC_RET"
        #trepr = linfo
    elif ttype == 'dynlib': # kernel32.GetProcAddress("user32.dll", 4248316)
        libname = tinfo
        trepr = "DLL_IMG_PTR" 
    elif ttype == 'dynfunc':
        libname,funcname = tinfo
        trepr = '%s.%s' % (libname,funcname)
    elif ttype == 'funcstack':
        stackoff = tinfo
        if self.funcva:
            flocal = self.vw.getFunctionLocal(self.funcva, stackoff)
            if flocal is not None:
                typename,argname = flocal
                return argname

        trepr = "LOCAL_BUFF" #'sp%s%d' % (o, abs(stackoff))
    elif ttype == 'apicall': # kernel32.TerminateProcess(1096396815, 3221226519)
        op, pc, api, argv = tinfo
        #if op.va in self.taintrepr: return '<0x%.8x>' % op.va
        rettype, retname, callconv, callname, callargs = api
        callstr = self.reprVivValue(pc)
        if not "." in callstr:
            return "FUNC_RET" 
        #argsstr = ','.join([self.reprVivValue(x) for x in argv])
        argsym = [symbolic_present(self, x) for x in argv]
        #trepr = '%s(%s)' % (callstr, argsstr)
        trepr = ("apicall", callstr, argsym)
        #self.taintrepr[op.va] = trepr
    else:
        trepr = 'taint: 0x%.8x %s %r' % (va, ttype, tinfo)

    return trepr

def symbolic_present(emu, val):
    # rewrite version of vivisect/impemu/emulator.py/reprVivValue() 
    # ref: https://github.com/vivisect/vivisect/blob/d6824f02b520969e83f6ce9ea8b585d8f0f7f317/vivisect/impemu/emulator.py#L655

    if emu.vw.isFunction(val):
        thunk = emu.vw.getFunctionMeta(val, 'Thunk')
        if thunk:
            return thunk

    vivname = emu.vw.getName(val)
    if vivname:
        return data_reprsent(emu, val)

    taint = emu.getVivTaint(val)
    if taint:
        va, ttype, tinfo = taint
        if ttype == 'apicall':
            op, pc, api, argv = tinfo
            rettype, retname, callconv, callname, callargs = api
            if val not in argv:
                return reprVivTaint(emu, taint)

        else:
            return reprVivTaint(emu, taint) #could be "kernel32.TlsGetValue" or "sp+n"

    stackoff = emu.getStackOffset(val)
    if stackoff is not None:
        funclocal = emu.vw.getFunctionLocal(emu.funcva, stackoff)
        if funclocal is not None:
            typename, varname = funclocal
            return varname
    if stackoff is not None:
        return "LOCAL_BUFF"

    if tryParseStrBuff := data_reprsent(emu, val):
        return tryParseStrBuff
    else:
        return '0x%.8x' % val

collect = {}
def fireComment(va, emu, apiName, argv):
    #print(f"{va:x} - {apiName}{argv}")
    #not any(x in apiName for x in ["sub_", "UnknownApi", "ntdll", "RtlSetLastWin32Error", "Tls", "InitializeCriticalSectionAndSpinCount", "Interlock"]):
    '''
    foundUnknownApi = False
    if "." in apiName:
        if apiName.split('.')[1].lower() in globals()['cur_iat_map']:
            return
        else:
            if "_" in  apiName.split('.')[1]:
                return
            foundUnknownApi = True
            #logger.debug(f"[!] WOW, dynamic loaded api -- {apiName}")
    #api = emu.getCallApi(va)
    #rtype, rname, convname, callname, funcargs = api
    #callconv = emu.getCallingConvention(convname)
    #argv = callconv.getCallArgs(emu, len(funcargs))
    '''
    '''
    maybePossibleMacroExist = False
    if True or "UnknownApi" in apiName or foundUnknownApi:
        #
        szArgv = []
        for a in callconv.getCallArgs(emu, 20): # force dump 20 argument
            cur_repr = symbolic_present(emu, a)
            maybePossibleMacroExist = maybePossibleMacroExist or ("0x" in cur_repr)
            szArgv.append( cur_repr )

        if maybePossibleMacroExist:
            collect[va] = (emu.funcva, szArgv)
            #print(f"[{va:x}] - {apiName}{tuple(szArgv)}")
    '''

    # ref: https://github.com/vivisect/vivisect/blob/50b249156e110a71aac1d96eca876b12b6221263/envi/__init__.py#L1012
    callconv = emu.getCallingConvention("stdcall")
    szArgv = []
    for a in callconv.getCallArgs(emu, 20): # force dump 20 argument
        cur_repr = symbolic_present(emu, a)
        szArgv.append( cur_repr )

    collect[va] = ( emu.funcva, apiName, szArgv, len(argv) )



# ref: https://github.com/vivisect/vivisect/blob/d6824f02b520969e83f6ce9ea8b585d8f0f7f317/vivisect/impemu/monitor.py#L152
def apicall(self, emu, op, pc, api, argv):

    rettype, retname, convname, callname, callargs = api
    if self.vw.getComment(op.va) is None:
        if callname is None:
            callname = self.vw.getName(pc)
        fireComment(op.va, emu, callname, argv)
        self.callcomments.append((op.va, callname, argv))

    # Record uninitialized register use
    for i, arg in enumerate(argv):

        # Check for taints first because it's faster...
        taint = emu.getVivTaint(arg)
        if taint:
            tva, ttype, tinfo = taint
            if ttype == 'uninitreg':
                emu.logUninitRegUse(tinfo)
            continue

        # Lets see if the API def has type info for us...
        if self.vw.isValidPointer(arg):
            argtype, argname = callargs[i]
            self.vw.setComment(arg, argtype, check=True)
            if not self.vw.isLocation(arg):
                if argname == 'funcptr':
                    self.vw.makeFunction(arg)

                # FIXME make an API for this? ( the name parsing )
                # Normalize and guess about the structure...
                typeguess = argtype.strip().strip('*').split()
                if typeguess[0] == 'struct' and len(typeguess) >= 2:
                    vs = self.vw.getStructure(arg, typeguess[1])
                    if vs is not None:
                        self.vw.makeStructure(arg, typeguess[1], vs=vs)

            continue

    # From here down, we are only checking for instances where the
    # emulator detected a call, and managed to resolve some code flow
    # that we failed to recognize statically...
    if pc == self.fva:
        self.vw.setFunctionMeta(self.fva, 'Recursive', True)
        return

    if self.vw.isFunction(pc):
        return

    # Ditch "call 0" constructs...
    if pc == op.va + len(op):
        return

    if not self.vw.isExecutable(pc):
        return

    # WOOT - we have found a runtime resolved function!
    self.vw.vprint('0x%.8x: Emulation Found 0x%.8x (from func: 0x%.8x) via %s' % (op.va, pc, self.fva, repr(op)))
    self.vw.makeFunction(pc, arch=op.iflags & envi.ARCH_MASK)
    REF_CODE   = 1 # A branch/call
    self.vw.addXref(op.va, pc, REF_CODE, envi.BR_PROC)

vivisect.impemu.monitor.AnalysisMonitor.apicall = apicall


class BasicBlock():
    def __init__(self, vw, va, size, fva):
        self.vw = vw
        self.va = va
        self.size = size
        self.fva = fva

    def instructions(self):
        ret = []
        va = self.va
        while va < self.va + self.size:
            try:
                o = self.vw.parseOpcode(va)
            except Exception as e:
                break
            ret.append(o)
            va += len(o)
        return ret

'''
    ref: https://github.com/angr/angr/blob/f356557a300922f0d54b50885f76fc191de5bf0d/angr/analyses/calling_convention.py#L334
    TODO: As the powerful project, Angr, still cannot fix the issue of determination the count of unknown function arguments
    via the calcutation on stack frame delta, I don't think that I'm smart enough to fix this issue too :(( 
'''
def getArgLenList(vw, funcAddr):
    collect = {}
    try:
        blocks = vw.getFunctionBlocks(funcAddr)
        for block in blocks:
            va, size, fva = block
            curva = va
            arglen = 0
            
            while curva < va + size:
                try:
                    o = vw.parseOpcode(curva)
                    if o.mnem == 'push' and ("ebp" not in str(o)):
                        arglen += 1
                    if o.isCall():
                        #print(f"{curva:x} - call argument len = {arglen}")
                        collect[curva] = arglen
                        arglen = 0 
                except Exception as e:
                    break
                curva += len(o)
    finally:
        pass
    return collect

import logging, re, pefile
import os, pathlib  
import coloredlogs, logging

logger = logging.getLogger(__name__)
pathlib.Path('poclog.txt').unlink(missing_ok=True)
logging.basicConfig(filename='scanlog.txt', level=logging.DEBUG)
coloredlogs.install(level='DEBUG', fmt='%(asctime)s [%(levelname)s] %(message)s',  datefmt='%H:%M:%S')

# disable vivsect alert.
def set_vivisect_log_level(level):
    logging.getLogger("vivisect").setLevel(level)
    logging.getLogger("vivisect.base").setLevel(level)
    logging.getLogger("vivisect.impemu").setLevel(level)
    logging.getLogger("vtrace").setLevel(level)
    logging.getLogger("envi").setLevel(level)
    logging.getLogger("envi.codeflow").setLevel(level)
set_vivisect_log_level(logging.CRITICAL)

def parseIat(pathToFile):
    ret = ''
    try:
        pfile = pefile.PE(pathToFile)
        for hmod in pfile.DIRECTORY_ENTRY_IMPORT:
            for imp in hmod.imports:
                ret += (imp.name.decode()).lower() + ";"    
    except:
        pass
    return ret

def dieIfUnwantExeBin(pathToFile, dieIfError = False) -> bool:
    with open(pathToFile, "rb") as dt:
        dt = dt.read().decode(encoding="latin-1").lower()
        if "msvbvm" in dt:
            logger.info("[!] fuck that VB6 binary. Bye.")
            if dieIfError: sys.exit(-1)
            return True
        if "borland" in dt or "delphi" in dt or "cbuilder" in dt:
            logger.info("[!] fuck that borland/delphi binary. Bye.")
            if dieIfError: sys.exit(-1)
            return True
    return False
# https://github.com/vivisect/vivisect/blob/50b249156e110a71aac1d96eca876b12b6221263/vivisect/tests/testimpapi.py#L14
import vivisect.impapi as viv_impapi 
imp = viv_impapi.getImportApi('windows','i386')
apiParamLenDB = {x.split(".")[1].lower(): len(imp._api_lookup[x][4]) for x in imp._api_lookup}

def scanSingleFile(pathToFile, libAtten, disp = True, dieIfError = False) -> list[str]:
    global collect, cur_iat_map, apiParamLenDB
    
    if dieIfUnwantExeBin(pathToFile, dieIfError): # Die if VB6 or BCB binaries
        return None
    
    cur_iat_map = parseIat(pathToFile)
    collect = {}
    vivisect.impemu.monitor.AnalysisMonitor.apicall = apicall
    vw = viv_utils.getWorkspace(pathToFile, analyze=False, should_save=False, verbose=True)

    if disp:
        baseaddr = vw.getFileMeta(vw.getFiles()[0], 'imagebase')
        logger.critical(f"[v] Exe ImageBase @ {baseaddr:x}")
        

    if vw.metadata['Architecture'] != "i386":
        if disp: logger.info("[!] Arch: " + vw.metadata['Architecture'] )
        if disp: logger.debug("Bye.")
        if dieIfError: sys.exit(-1)
        else: return None
    
    vw.analyze()

    unknownPtrList = dict()
    for va, _ in collect.items():
        funcva, apiname, symbolic_argv, orginal_arglen = _

        if  ("UnknownApi" in apiname) or \
            ( "." in apiname and not ("_" in  apiname.split('.')[1]) ):

            #print(f"[!] WOW, dynamic loaded api -- {apiname}")
            unknownPtrList[va] = funcva, apiname, symbolic_argv, orginal_arglen
            
    if disp:
        logger.critical(f"[!] found {len(unknownPtrList)} unknown ptr from {len(collect)} func calls!")

    ret_collect = list()
    for va, _ in unknownPtrList.items():
        funcva, apiname, symbolic_argv, orginal_arglen = _
        try:
            decompileArgLen = getArgLenList(vw, funcva)[va]
            szArgv = symbolic_argv[: decompileArgLen]
            if decompileArgLen < 3: continue
            if ans:= libAtten.predictApiList (szArgv):
                enumList = ans
                enumList = [a for a in ans if abs ( apiParamLenDB[a.lower()] - decompileArgLen) <= 2] # TODO: arguments decompile not always correct.
                #enumList = [a for a in ans if apiParamLenDB[a.lower()] > 2] # only those APIs with 4+ args easy to predict. 
                if len(enumList) > 0:
                    if disp: logger.warning(f"[FOUND] ({va:x}) - {', '.join(enumList[:3])}")
                    ret_collect += enumList
            
        except Exception as e:
            pass
    return ret_collect


'''
    Use Emulation Method to record all the possible on-the-stack values used on the unknown pointers.
'''
class shellcodeEmulator():
    
    def __init__(self, pathToShellcode, arch, **kwargs):
        self.vw = viv_utils.getShellcodeWorkspaceFromFile( pathToShellcode, arch )
        self.emu = self.vw.getEmulator()
        self.collect = {}
        self.apiArgLenDB = {}
    
    def _fireComment(self, emu, va, op, iscall, callMeta):
        '''
        # Branch flags (flags returned by the getBranches() method on an opcode)
        BR_PROC  = 1<<0  # The branch target is a procedure (call <foo>)
        BR_COND  = 1<<1  # The branch target is conditional (jz <foo>)
        BR_DEREF = 1<<2  # the branch target is *dereferenced* into PC (call [0x41414141])
        BR_TABLE = 1<<3  # The branch target is the base of a pointer array of jmp/call slots
        BR_FALL  = 1<<4  # The branch is a "fall through" to the next instruction
        BR_ARCH  = 1<<5  # The branch *switches opcode formats*. ( ARCH_FOO in high bits )
        '''
        v1 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_PROC)
        v2 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_COND)
        v3 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_DEREF)
        v4 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_TABLE)
        v5 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_FALL)
        v6 = any(branch for branch, flag in op.getBranches() if flag & envi.BR_ARCH)

        apiName, argv = callMeta
        unknownApiExist = (bool(op.iflags & envi.IF_NOFALL) or bool(op.iflags & envi.IF_CALL)) and not bool(op.iflags & envi.IF_RET)

        if unknownApiExist and not (v1 or v2):
            szArgv = []
            callconv = emu.getCallingConvention("msx64call" if emu.vw.getMeta('Architecture') == "amd64" else "stdcall") 
            for a in callconv.getCallArgs(emu, 20): # force dump 20 argument
                cur_repr = symbolic_present(emu, a)
                szArgv.append( cur_repr )

            self.collect[va] = (emu.funcva, szArgv)
        return False
                
    # rewrite from vivisect.impemu.emulator.runFunction.
    def _funcTinyRunner(self, funcva, _currDepth = 0, _givenSnap = None):
        if _givenSnap: self.emu.setEmuSnap(_givenSnap)
        self.emu.funcva = funcva
        if _currDepth > 3: return
        # Let the current (should be base also) path know where we are starting
        vg_path.setNodeProp(self.emu.curpath, 'bva', funcva)
        hits = {}
        modifyState = False
        todo = [(funcva, self.emu.getEmuSnap(), self.emu.path)]
        vw = self.emu.vw  # Save a dereference many many times

        while len(todo):

            va, esnap, self.emu.curpath = todo.pop()
            self.emu.setEmuSnap(esnap)
            self.emu.setProgramCounter(va)

            while True:
                starteip = self.emu.getProgramCounter()
                if not vw.isValidPointer(starteip): break

                # maxhit = 1
                if starteip in hits: break
                hits[starteip] = 1

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow)?
                if self.emu.curpath is None: break
                try:
                    op = self.emu.parseOpcode(starteip)
                    iscall = bool(op.iflags & envi.IF_CALL)
                    self.emu.op = op

                    self.emu.executeOpcode(op)
                    vg_path.getNodeProp(self.emu.curpath, 'valist').append(starteip)
                    endeip = self.emu.getProgramCounter()

                    # leak invoked call's arguments.
                    rtype, rname, convname, callname, funcargs = self.emu.getCallApi(endeip)
                    callname = f"sub_{endeip:x}" if callname == None else callname
                    callconv = self.emu.getCallingConvention("msx64call" if self.emu.vw.getMeta('Architecture') == "amd64" else "stdcall") 

                    if len(funcargs) < 1 and ('sub_' in callname or callname == 'UnknownApi'):
                        argv = callname, callconv.getCallArgs(self.emu, 12) # dump max 12 stack values.
                    else:
                        argv = callname, callconv.getCallArgs(self.emu, len(funcargs))  # normal fetch argument info.
                    self._fireComment(self.emu, starteip, op, iscall, argv)
                    
                    # simulate the call.
                    if iscall:
                        currSnap = self.emu.getEmuSnap()
                        if not self._funcTinyRunner(endeip, _currDepth + 1, currSnap):
                            self.emu.setEmuSnap(currSnap)
        
                    self.emu.checkCall(starteip, endeip, op)
                    ret = callconv.getReturnValue(self.emu)
                    
   
                    if self.emu.emustop: return

                    # If it wasn't a call, check for branches, if so, add them to the todo list and go around again...
                    if not iscall:
                        blist = self.emu.checkBranches(starteip, endeip, op)
                        if len(blist):
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.emu.getEmuSnap()
                            for bva, bpath in blist:
                                todo.append((bva, esnap, bpath))
                            break

                    # If we enounter a procedure exit, it doesn't matter what EIP is, we're done here.
                    if op.iflags & envi.IF_RET:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', True)
                        break
                    if self.emu.vw.isNoReturnVa(op.va) and op.va != funcva:
                        vg_path.setNodeProp(self.emu.curpath, 'cleanret', False)
                        break

                
                except envi.BadOpcode:
                    break
                except envi.UnsupportedInstruction as e:
                    if self.emu.strictops:
                        #print('runFunction failed: unsupported instruction - 0x%08x %s' %(e.op.va, e.op.mnem)) 
                        break
                    else:
                        #print('runFunction continuing after unsupported instruction - 0x%08x %s' % (e.op.va, e.op.mnem))
                        self.emu.setProgramCounter(e.op.va + e.op.size)
                except v_exc.BadOutInstruction:
                    break

                except e_exc.BreakpointHit:
                    pass # drop bp.
            
                except Exception as e:
                    #print(e)
                    if self.emu.emumon is not None and not isinstance(e, e_exc.BreakpointHit):
                        self.emu.emumon.logAnomaly(self, starteip, str(e))

                    break  # If we exc during execution, this branch is dead.


        return modifyState
    
    def runAnalyze(self):    
        for fn in self.vw.getFunctions():
            self._funcTinyRunner(fn)
            tmpList = getArgLenList(self.vw, fn)
            self.apiArgLenDB.update(tmpList)
        return self.collect
