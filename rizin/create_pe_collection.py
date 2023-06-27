import os

def get_exe_paths(exe_paths):
    if not os.path.exists(exe_paths):
        raise IOError(f"signatures path {exe_paths} does not exist or cannot be accessed")

    paths = []
    if os.path.isfile(exe_paths):
        paths.append(exe_paths)
    elif os.path.isdir(exe_paths):
        for root, _, files in os.walk(exe_paths):
            for file in files:
                if file.endswith((".exe_")):
                    sig_path = os.path.join(root, file)
                    paths.append(sig_path)

    # nicely normalize and format path so that debugging messages are clearer
    paths = [os.path.abspath(os.path.normpath(path)) for path in paths]

    # load signatures in deterministic order: the alphabetic sorting of filename.
    # this means that `0_sigs.pat` loads before `1_sigs.pat`.
    paths = sorted(paths, key=os.path.basename)

    return paths

paths = get_exe_paths("tests/data/")
with open("rizin/sample_exes.txt", "w") as f:
    for path in paths:
        f.write(path + "\n")

