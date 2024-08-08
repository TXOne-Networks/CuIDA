import concurrent.futures, os, sys, time, types
from rich.console import Console
console = Console()

def shcEmuScan( pathToShc:str , shcPtr_CallConv_Formatter:types.FunctionType ):
    import lib.scan, lib.attention
    pathToModel = os.path.join(os.path.dirname(__file__) + "\\lib", 'model32.cuida')
    lib.attention.loadModel_lastCheckpoint(pathToModel=pathToModel)
    
    shcEmu = lib.scan.shellcodeEmulator( pathToShc, "i386" )
    collect = shcEmu.runAnalyze()

    for va in collect:
        funcva, szArgv = collect[va]
        try:

            if decompileArgLen := shcEmu.apiArgLenDB.get(va):
                szArgv, correctArgLen = shcPtr_CallConv_Formatter(szArgv, decompileArgLen)
                if ans:= lib.attention.predictApiList (szArgv):
                    enumList = ans
                    enumList = [a for a in ans if lib.scan.apiParamLenDB[a.lower()] == correctArgLen]
                    enumList = [a for a in ans if lib.scan.apiParamLenDB[a.lower()] > 3] # only those APIs with 4+ args easy to predict. 
                    if len(enumList) > 0:
                        console.print(f"[b][‼] [default]{va:05x}: {', '.join(enumList)}", style="green")
        except Exception as e:
            print(e)
            pass

if __name__ == "__main__":
    if True:
        if len(sys.argv) == 1:
            print("Usage: ./nnShellcode.py [Path/To/Shc]")
            sys.exit(0)
    
    init_time = time.time()
        
    # Customized Template to format the use of arguments by Cabalt Strike 
    # into correct Win32 API execution calling convention.
    def callconvTemplate_CabaltStrike( dump_argv, decompile_callee_arglen ):
        
        # *(executeWin32api_byHash*)( E553A458h, v4, 0x400000, 4096, 64);
        #                             ^^^^^^^^^
        #                    Magic Number of VirtualAlloc
        #
        # >>> consider that Cabalt Strike Beacon occupied the first parameter to record magic number
        # >>> The correct argument count should be 4 for VirtualAlloc, instead of 5 arguments!
        #      
        ret_argv = dump_argv[ 1: decompile_callee_arglen ]
        ret_arglen = decompile_callee_arglen - 1
        return (ret_argv, ret_arglen)

    if os.path.isfile( sys.argv[1] ): 
        SHELLCODE_BASE = 0x690000
        console.print("[DEFAULT] Choose calling convention template of Cabalt Strike", style="dim blue")
        console.print(f"[DEFAULT] Shellcode Base @ {SHELLCODE_BASE:x}", style="yellow")
        shcEmuScan( sys.argv[1], shcPtr_CallConv_Formatter= callconvTemplate_CabaltStrike )
    else:
        console.print("[?] Path Incorrect? Should be Exe file to Scan")

    console.print(f"[v] total cost {time.time() - init_time:.2f} sec.")