#pip install yara-python
import yara, os, glob, json, time, sys
from rich.console import Console
console = Console()  
from rich.tree import Tree

def yaraScanFile( pathToSample ):
    ret = lib.scan.scanSingleFile( pathToSample, lib.attention, 
                                   disp="-display" in sys.argv, dieIfError=False )
    ret = '\x00'.join(set(ret)).encode()

    # Pure YARA Detection
    binaryData = open(pathToSample, 'rb').read()
    mt = rules.match(data=binaryData)
    pureYaraRet = set([str(m) for m in mt])
    
    # nnYARA Detection
    mt = rules.match(data=binaryData + ret)
    nnYaraRet = set([str(m) for m in mt])

    if not "-json" in sys.argv:
        from rich.panel import Panel
        tree = Tree(
            f":open_file_folder: [link file://{pathToSample}]{os.path.basename(pathToSample)}",
            guide_style="bold bright_blue",
        )
        pureYaraNode = tree.add(f"Pure YARA Detect {len(pureYaraRet)} Unqiue Techniques")
        pureYaraNode.add( Panel('\x20'.join(pureYaraRet)) )
        nnYaraNode = tree.add(f"nnYARA Detect {len(nnYaraRet)} Unqiue Techniques")
        nnYaraNode.add( Panel('\x20'.join(nnYaraRet)) )

        extraFilter = tree.add(f"nnYARA Detect Extra {len(nnYaraRet) - len(pureYaraRet)} Hidden Behaviors", style="on red bold")
        extraFilter.add( Panel(', '.join(nnYaraRet - pureYaraRet)) )
        console.print(tree)
    else:
        collect = dict()
        collect['sample'] = pathToSample
        collect['yara_scan'] = [ str(x) for x in pureYaraRet ]
        collect['nnyara_scan'] = [str(x) for x in nnYaraRet]
        collect['hidden_ptr_detect'] = [str(x) for x in (nnYaraRet - pureYaraRet)]
        console.print_json( json.dumps(collect) )

if __name__ == "__main__":
    if True:
        if len(sys.argv) == 1:
            print("Usage: ./nnYara.py [Path/To/File] (-display) (-json: Output as JSON format)")
            sys.exit(0)
    
    # attach community yara-rules!
    # ref: https://github.com/pombredanne/yara_scan/blob/master/yara_scan.py
    global all_rules
    try:
        def test_rule(test_case):
            try:
                testit = yara.compile(filepath=test_case)
                return True
            except: return False
        all_rules = {}
        
        pathToRules = os.path.join( os.path.dirname(__file__) + "\\lib", "yara-rules" )
        sigfiles = list( glob.glob(f"{pathToRules}/**/*.yar", recursive=True) )
        for root, directories, files in os.walk(pathToRules):
            for file in files:
                if "yar" in os.path.splitext(file)[1]:
                    rule_case = os.path.join(root,file) 
                    if test_rule(rule_case):
                        all_rules[file] = rule_case
        rules = yara.compile(filepaths=all_rules)
    except Exception as e:
        pass
    
    import lib.scan, lib.attention

    init_time = time.time()
    pathToModel = os.path.join(os.path.dirname(__file__) + "\\lib", 'model32.cuida')
    lib.attention.loadModel_lastCheckpoint(pathToModel=pathToModel)

    if os.path.isfile( sys.argv[1] ): 
        yaraScanFile( sys.argv[1] )
    else:
        print("[?] Path Incorrect? Should be Exe file to Scan")
    
    console.print(f"[v] total cost {time.time() - init_time:.2f} sec.")