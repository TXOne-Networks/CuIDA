
#  py .\lib\scan.py ..\0c61cba7ead9c67c5d0838aa76cee95e_dump.exe
import yara, os, glob, subprocess, json, shutil, time, concurrent, sys
import logging, sys, time, pathlib
import concurrent.futures
import coloredlogs, logging

logger = logging.getLogger(__name__)
pathlib.Path('poclog.txt').unlink(missing_ok=True)
logging.basicConfig(filename='scanlog.txt', level=logging.DEBUG)
coloredlogs.install(level='DEBUG', fmt='%(asctime)s [%(levelname)s] %(message)s',  datefmt='%H:%M:%S')

def dumpPeImageByPeSieve(pid:int) -> str:
    # thanks for awesome tool PE-Sieve by @hasherezade
    # ref: https://github.com/hasherezade/pe-sieve
    # $ pe-sieve.exe /pid 32184 /dir pathToDir
    pathToPeSieve = os.path.join( os.path.dirname(__file__) + "\\lib", "pe-sieve.exe" )
    pathToTmpDump = os.path.join( os.path.dirname(__file__) + "\\lib" )
    STR_OUT = subprocess.getoutput( f"{pathToPeSieve} /pid {pid} /dir {pathToTmpDump}" )
    if not "Dumped module to" in STR_OUT:
        return None

    JSON_REPORT = os.path.join( os.path.dirname(__file__), "lib", f"process_{pid}", "dump_report.json")
    JSON_REPORT = json.load(open(JSON_REPORT))
    pathToDumpedFile = JSON_REPORT.get("dumps")[0].get('dump_file')
    pathToDumpedFile = os.path.join( os.path.dirname(__file__), "lib", f"process_{pid}", pathToDumpedFile)
    return pathToDumpedFile if os.path.isfile(pathToDumpedFile) else None


if __name__ == "__main__":

    if True:
        if len(sys.argv) != 2:
            print("Usage: ./nnSymUnpacker.py [PID || Path/To/DumpExe ]")
            sys.exit(0)

    init_time = time.time()    
    import lib.scan, lib.attention
    
    pathToModel = os.path.join(os.path.dirname(__file__) + "\\lib", 'model32.cuida')
    lib.attention.loadModel_lastCheckpoint(pathToModel=pathToModel)
    
    if os.path.isfile( sys.argv[1] ):
        pathToFile = sys.argv[1]
        print(f"[v] Scan Input Dump Exe @", *pathToFile.split("\\")[-3: ])
    else:
        # clean those left old dummy since last scanning.
        for p in glob.glob( os.path.join( os.path.dirname(__file__), "lib", "process_*" ), recursive=True):
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            
        if getDumpExePath := dumpPeImageByPeSieve( pid= int(sys.argv[1]) ):    
            pathToFile = getDumpExePath
            #pathToFile = pathToSample
            print(f"[v] Mem Dump @", os.path.join(*pathToFile.split("\\")[-3: ]))
        else:
            print(f"[!] Process Die Yet? Incorrect PID to Dump Mem :( ")
            sys.exit(1)


    lib.scan.scanSingleFile( pathToFile, lib.attention, disp=True, dieIfError=True )

    logger.info(f"[v] total cost {time.time() - init_time:.2f} sec.")