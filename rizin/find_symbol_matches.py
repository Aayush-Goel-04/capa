#!/usr/bin/env python3
"""
    $ python3 rizin/find_symbol_matches.py rizin/sample_exes.txt --signature sigs/
    $ python3 rizin/find_symbol_matches.py rizin/sample_exes.txt --signature rizin/sigdb/
"""
import sys
import logging
import argparse

import flirt
import viv_utils
import viv_utils.flirt

import capa.main
import capa.rules
import capa.engine
import capa.helpers
import capa.features
import capa.features.freeze
import tqdm

logger = logging.getLogger("capa.match-function-id")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(description="FLIRT match each function")
    parser.add_argument("sample", type=str, help="File containing Paths to sample to analyze")
    parser.add_argument(
        "-F",
        "--function",
        type=lambda x: int(x, 0x10),
        help="match a specific function by VA, rather than add functions",
    )
    parser.add_argument(
        "--signature",
        action="append",
        dest="signatures",
        type=str,
        default=[],
        help="use the given signatures to identify library functions, file system paths to .sig/.pat files.",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debugging output on STDERR")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable all output but errors")
    args = parser.parse_args(args=argv)

    if args.quiet:
        logging.basicConfig(level=logging.ERROR)
        logging.getLogger().setLevel(logging.ERROR)
    elif args.debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().setLevel(logging.INFO)

    # disable vivisect-related logging, it's verbose and not relevant for capa users
    capa.main.set_vivisect_log_level(logging.CRITICAL)

    # Create analyzers based on sigs paths
    analyzers = []
    sig_paths = []
    for sig_dir_path in args.signatures:
        sig_paths += capa.main.get_signatures(sig_dir_path)

    for sigpath in sig_paths:
        print(sigpath)
        sigs = viv_utils.flirt.load_flirt_signature(sigpath)

        with capa.main.timing("flirt: compiling sigs"):
            matcher = flirt.compile(sigs)

        analyzer = viv_utils.flirt.FlirtFunctionAnalyzer(matcher, sigpath)
        logger.debug("registering viv function analyzer: %s", repr(analyzer))
        analyzers.append(analyzer)

    new_file = "rizin/match_for_new_sigs.txt"
    new_founds = "rizin/allFounds_rizin_sigs.txt"
    if "sigs" in args.signatures[0]:
        new_file =  "rizin/match_for_current_sigs.txt"
        new_founds = "rizin/allFounds_capa_sigs.txt"

    new_dir = "rizin/function_matches_rizin_sigs/"
    if "sigs" in args.signatures[0]:
        new_dir =  "rizin/function_matches_capa_sigs/"
    
    # with open(new_file, 'w'):
    #     pass
    
    overall_founds = []
    with capa.helpers.redirecting_print_to_tqdm(False):
        with tqdm.contrib.logging.logging_redirect_tqdm():
            try:
                with open(args.sample, 'r') as input:
                    pbar = tqdm.tqdm
                    print("started analyzing sample exes paths")
                    
                    paths = [path.strip() for path in input.readlines()]
                    pb = pbar(paths, desc="matching")
                    i = 1
                    for path in pb:
                        vw = viv_utils.getWorkspace(path, analyze=True, should_save=False)
                        
                        functions = vw.getFunctions()
                        if args.function:
                            functions = [args.function]
                        function_matches = 0
                        found = []
                        for function in functions:
                            logger.debug("matching function: 0x%04x", function)
                            for analyzer in analyzers:
                                name = viv_utils.flirt.match_function_flirt_signatures(analyzer.matcher, vw, function)
                                if name and name not in found:
                                    function_matches += 1 
                                    found.append(name)
                                    if name not in overall_founds:
                                        overall_founds.append(name)
                        s = str(i)+ " , " +path + " , " + str(function_matches) + "\n"         
                        with open(new_file, 'a') as f:
                            f.write(s)
                        with open(new_dir+path.split("/")[-1]+".txt", 'w') as f:
                            for m in found:
                                f.write(str(m) + "\n") 
                        i+=1
                    with open(new_founds, 'w') as f:
                        for m in overall_founds:
                            f.write(str(m) + "\n") 
                    print(len(overall_founds))
            except Exception as e:
                s = path + " , " + str(e) + "\n"         
                with open(new_file, 'a') as f:
                    f.write(s)
                i+=1

    return 0


if __name__ == "__main__":
    sys.exit(main())
