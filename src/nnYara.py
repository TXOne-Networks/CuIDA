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
            print("Usage: ./nnYara.py [Path/To/File] (-display) (-json) (--rules Path/To/YaraRules)")
            sys.exit(0)
    
    # attach community yara-rules!
    # ref: https://github.com/pombredanne/yara_scan/blob/master/yara_scan.py
    #
    # The ruleset is deliberately not vendored (size + upstream licensing).
    # Point CuIDA at any directory of *.yar files, in priority order:
    #   --rules <dir>  >  $CUIDA_YARA_RULES  >  src/lib/yara-rules/
    pathToRules = ( os.environ.get("CUIDA_YARA_RULES")
                    or os.path.join( os.path.dirname(os.path.abspath(__file__)), "lib", "yara-rules" ) )
    for flag in ("--rules", "-rules"):
        if flag in sys.argv and sys.argv.index(flag) + 1 < len(sys.argv):
            pathToRules = sys.argv[ sys.argv.index(flag) + 1 ]

    if not os.path.isdir(pathToRules):
        console.print(f"[!] YARA rule directory not found: {pathToRules}", style="bold red")
        console.print("    Clone a community ruleset, e.g.:", style="dim")
        console.print(f"      git clone --depth 1 https://github.com/Yara-Rules/rules {pathToRules}", style="dim")
        console.print("    ...or pass --rules <dir>, or set $CUIDA_YARA_RULES.", style="dim")
        sys.exit(1)

    def test_rule(test_case):
        try:
            yara.compile(filepath=test_case)
            return True
        except Exception:
            return False

    all_rules, uncompilable = {}, 0
    for root, directories, files in os.walk(pathToRules):
        for file in files:
            if "yar" in os.path.splitext(file)[1]:
                rule_case = os.path.join(root, file)
                if test_rule(rule_case):
                    all_rules[file] = rule_case
                else:
                    uncompilable += 1

    if not all_rules:
        console.print(f"[!] No compilable *.yar file found under {pathToRules}", style="bold red")
        sys.exit(1)

    rules = yara.compile(filepaths=all_rules)
    console.print(f"[v] {len(all_rules)} YARA rule files loaded from {pathToRules}"
                  + (f" ({uncompilable} skipped: upstream rules that do not compile)" if uncompilable else ""),
                  style="dim blue")


    import lib.scan, lib.attention

    init_time = time.time()
    lib.attention.loadModel_lastCheckpoint()

    if os.path.isfile( sys.argv[1] ): 
        yaraScanFile( sys.argv[1] )
    else:
        print("[?] Path Incorrect? Should be Exe file to Scan")
    
    console.print(f"[v] total cost {time.time() - init_time:.2f} sec.")