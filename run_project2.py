#!/usr/bin/env python3
"""
CRYE6135 - Session 2 - Project 2
Gate Equivalents (GE) of small lightweight-crypto blocks: hand count vs real
Yosys synthesis on three real open-source standard-cell libraries.

Designs : PRESENT 4-bit S-box, one PRESENT round (64-bit), 32-bit XOR-rotate,
          plus the AES 8-bit S-box as a reference point.
Techs   : Nangate 45 nm, SkyWater 130 nm, GlobalFoundries 180 nm (real .lib files)
Needs   : python3, matplotlib, and Yosys (`yosys` or `yowasp-yosys` on PATH).
          Windows:  pip install yowasp-yosys matplotlib
Run     : python run_project2.py        (first run downloads ~40 MB of libraries)
"""
import csv, gzip, random, re, shutil, subprocess, sys, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RTL, LIBS, WORK, OUT = ROOT / "rtl", ROOT / "libs", ROOT / "work", ROOT / "results"
for d in (RTL, LIBS, WORK, OUT):
    d.mkdir(exist_ok=True)

# --------------------------------------------------------------------------- #
# 0. Technologies (real Liberty files from the OpenROAD-flow-scripts repo)
# --------------------------------------------------------------------------- #
ORFS = "https://raw.githubusercontent.com/The-OpenROAD-Project/OpenROAD-flow-scripts/master/flow/platforms/"
TECHS = [
    dict(key="nangate45", label="Nangate 45 nm", nm=45,
         url=ORFS + "nangate45/lib/NangateOpenCellLibrary_typical.lib", gz=False,
         pat=lambda f: rf"^{f}_X\d+$"),
    dict(key="sky130hd", label="SkyWater 130 nm", nm=130,
         url=ORFS + "sky130hd/lib/sky130_fd_sc_hd__tt_025C_1v80.lib", gz=False,
         pat=lambda f: rf"^sky130_fd_sc_hd__{f.lower()}_\d+$"),
    dict(key="gf180", label="GlobalFoundries 180 nm", nm=180,
         url=ORFS + "gf180/lib/gf180mcu_fd_sc_mcu7t5v0__tt_025C_5v00.lib.gz", gz=True,
         pat=lambda f: rf"^gf180mcu_fd_sc_mcu7t5v0__{f.lower()}_\d+$"),
]
FUNCS = ["INV", "NAND2", "NOR2", "AND2", "OR2", "XOR2", "XNOR2", "DFF"]
FUNC_PAT = {"DFF": {"nangate45": r"^DFF_X\d+$", "sky130hd": r"^sky130_fd_sc_hd__dfxtp_\d+$",
                    "gf180": r"^gf180mcu_fd_sc_mcu7t5v0__dffq_\d+$"}}


def get_lib(t):
    path = LIBS / f"{t['key']}.lib"
    if not path.exists():
        print(f"  downloading {t['label']} library ...")
        raw = urllib.request.urlopen(t["url"], timeout=120).read()
        path.write_bytes(gzip.decompress(raw) if t["gz"] else raw)
    return path


def read_cell_areas(path):
    txt = path.read_text(errors="ignore")
    areas = {}
    for m in re.finditer(r'\bcell\s*\(\s*"?([^")\s]+)"?\s*\)\s*\{', txt):
        a = re.compile(r"\barea\s*:\s*([0-9.eE+-]+)").search(txt, m.end())
        if a:
            areas[m.group(1)] = float(a.group(1))
    return areas


def tech_info(t):
    """NAND2 area (= 1 GE) and the GE weight of the basic cells, straight from the .lib."""
    areas = read_cell_areas(get_lib(t))

    def smallest(func):
        pat = FUNC_PAT[func][t["key"]] if func in FUNC_PAT else t["pat"](func)
        c = [(a, n) for n, a in areas.items() if re.match(pat, n)]
        return min(c)[0]
    nand = smallest("NAND2")
    return dict(nand=nand, ratio={f: smallest(f) / nand for f in FUNCS})


# --------------------------------------------------------------------------- #
# 1. Reference models (Python) - validated against the official PRESENT vectors
# --------------------------------------------------------------------------- #
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]


def p_layer(s):
    o = 0
    for i in range(64):
        o |= ((s >> i) & 1) << (63 if i == 63 else (16 * i) % 63)
    return o


def sbox_layer(s):
    return sum(SBOX[(s >> (4 * i)) & 0xF] << (4 * i) for i in range(16))


def present_round_ref(state, rk):
    return p_layer(sbox_layer(state ^ rk))


def present80(pt, key):
    k, s = key, pt
    for r in range(1, 32):
        s = present_round_ref(s, k >> 16)
        k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
        k = (SBOX[k >> 76] << 76) | (k & ((1 << 76) - 1))
        k ^= r << 15
    return s ^ (k >> 16)


def check_reference():
    M = (1 << 64) - 1
    K = (1 << 80) - 1
    vec = [(0, 0, 0x5579C1387B228445), (0, K, 0xE72C46C0F5945049),
           (M, 0, 0xA112FFC72F68417B), (M, K, 0x3333DCD3213210D2)]
    assert all(present80(pt, k) == ct for pt, k, ct in vec)
    print("[ok] Python PRESENT model matches the 4 official test vectors "
          "(so S-box table and pLayer are right)")


def aes_sbox():
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r
    inv = [0] + [next(y for y in range(1, 256) if mul(x, y) == 1) for x in range(1, 256)]
    rot = lambda v, n: ((v << n) | (v >> (8 - n))) & 0xFF
    return [i ^ rot(i, 1) ^ rot(i, 2) ^ rot(i, 3) ^ rot(i, 4) ^ 0x63 for i in inv]


# --------------------------------------------------------------------------- #
# 2. Hand-counted S-box netlist (single source of truth: counted AND simulated)
#    Gate = (output, type, inputs...).  This is the "by hand" design.
# --------------------------------------------------------------------------- #
HAND = [
    ("n0", "INV", "x0"), ("n1", "INV", "x1"), ("n2", "INV", "x2"), ("n3", "INV", "x3"),
    ("a0", "AND2", "x1", "x0"), ("a1", "AND2", "x2", "n1"), ("a2", "AND2", "x1", "n0"),
    ("o0", "OR2", "x1", "x0"), ("o20", "OR2", "x2", "x0"),
    # y0 = x3 ^ x0 ^ (x2 & ~x1)
    ("t", "XOR2", "x3", "x0"), ("y0", "XOR2", "t", "a1"),
    # y1
    ("q1", "NAND2", "x2", "n0"), ("b1", "AND2", "x3", "q1"), ("b2", "AND2", "n3", "a2"),
    ("m1", "OR2", "b1", "b2"), ("c", "AND2", "n2", "a0"), ("y1", "XOR2", "m1", "c"),
    # y2
    ("d1", "AND2", "x3", "x1"), ("d2", "AND2", "n3", "n2"), ("m2a", "OR2", "d1", "d2"),
    ("e1", "AND2", "x3", "o20"), ("e2", "AND2", "n3", "a0"), ("m2b", "OR2", "e1", "e2"),
    ("y2", "XOR2", "m2a", "m2b"),
    # y3
    ("f", "OR2", "x2", "n1"), ("g", "AND2", "n0", "f"), ("y30", "OR2", "a0", "g"),
    ("y31", "AND2", "n2", "o0"), ("h1", "AND2", "n3", "y30"), ("h2", "AND2", "x3", "y31"),
    ("y3", "OR2", "h1", "h2"),
]
EVAL = {"INV": lambda a: 1 ^ a, "AND2": lambda a, b: a & b, "OR2": lambda a, b: a | b,
        "NAND2": lambda a, b: 1 ^ (a & b), "XOR2": lambda a, b: a ^ b}
VOP = {"AND2": "{} & {}", "OR2": "{} | {}", "NAND2": "~({} & {})", "XOR2": "{} ^ {}", "INV": "~{}"}
TEXTBOOK = {"INV": 2 / 3, "NAND2": 1.0, "NOR2": 1.0, "AND2": 4 / 3, "OR2": 4 / 3, "XOR2": 2.0}


def hand_sbox(v):
    w = {f"x{i}": (v >> i) & 1 for i in range(4)}
    for out, g, *ins in HAND:
        w[out] = EVAL[g](*[w[i] for i in ins])
    return sum(w[f"y{i}"] << i for i in range(4))


def hand_counts():
    c = {}
    for _, g, *_ in HAND:
        c[g] = c.get(g, 0) + 1
    return c


def hand_ge(ratio):
    return sum(n * ratio[g] for g, n in hand_counts().items())


def hand_verilog():
    L = ["// Hand-built gate-level PRESENT S-box (31 gates). Same function as present_sbox.",
         "module present_sbox_hand (input wire [3:0] x, output wire [3:0] y);",
         "  wire x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];"]
    for out, g, *ins in HAND:
        L.append(f"  wire {out} = {VOP[g].format(*ins)};")
    L += ["  assign y = {y3, y2, y1, y0};", "endmodule"]
    return "\n".join(L) + "\n"


def check_hand():
    assert [hand_sbox(v) for v in range(16)] == SBOX
    print("[ok] hand-built S-box netlist = PRESENT S-box on all 16 inputs "
          f"({sum(hand_counts().values())} gates)")


# --------------------------------------------------------------------------- #
# 3. RTL files
# --------------------------------------------------------------------------- #
def write_rtl():
    case = " ".join(f"4'h{i:X}: y = 4'h{v:X};" for i, v in enumerate(SBOX))
    (RTL / "present_sbox.v").write_text(
        "// PRESENT 4-bit S-box, truth table (ISO/IEC 29192-2)\n"
        "module present_sbox (input wire [3:0] x, output reg [3:0] y);\n"
        f"  always @* case (x) {case} endcase\nendmodule\n")
    (RTL / "present_round.v").write_text(
        "// One PRESENT round: addRoundKey -> 16 S-boxes -> pLayer (pure wiring)\n"
        "module present_round (input wire [63:0] state_in, input wire [63:0] round_key,\n"
        "                      output wire [63:0] state_out);\n"
        "  wire [63:0] ark = state_in ^ round_key;\n  wire [63:0] sb;\n  genvar i;\n  generate\n"
        "    for (i = 0; i < 16; i = i + 1) begin : g_sbox\n"
        "      present_sbox u (.x(ark[4*i+3:4*i]), .y(sb[4*i+3:4*i]));\n    end\n"
        "    for (i = 0; i < 63; i = i + 1) begin : g_player\n"
        "      assign state_out[(16*i) % 63] = sb[i];\n    end\n  endgenerate\n"
        "  assign state_out[63] = sb[63];\nendmodule\n")
    (RTL / "xor_rot32.v").write_text(
        "// Y = (A ^ B) <<< 7 : 32 XORs, the rotation is pure wiring\n"
        "module xor_rot32 (input wire [31:0] a, input wire [31:0] b, output wire [31:0] y);\n"
        "  wire [31:0] x = a ^ b;\n  assign y = {x[24:0], x[31:25]};\nendmodule\n")
    (RTL / "present_sbox_hand.v").write_text(hand_verilog())
    case = " ".join(f"8'h{i:02X}: y = 8'h{v:02X};" for i, v in enumerate(aes_sbox()))
    (RTL / "aes_sbox.v").write_text(
        "// AES 8-bit S-box as a plain lookup table (reference point)\n"
        "module aes_sbox (input wire [7:0] x, output reg [7:0] y);\n"
        f"  always @* case (x) {case} endcase\nendmodule\n")


DESIGNS = {  # name -> (top, rtl files)
    "present_sbox": ("present_sbox", ["present_sbox.v"]),
    "present_round": ("present_round", ["present_sbox.v", "present_round.v"]),
    "xor_rot32": ("xor_rot32", ["xor_rot32.v"]),
    "aes_sbox": ("aes_sbox", ["aes_sbox.v"]),
}
LABEL = {"xor_rot32": "32-bit XOR-rotate", "present_sbox": "PRESENT S-box (4-bit)",
         "present_round": "PRESENT round (64-bit)", "aes_sbox": "AES S-box (8-bit)"}


# --------------------------------------------------------------------------- #
# 4. Yosys helpers
# --------------------------------------------------------------------------- #
YOSYS = shutil.which("yosys") or shutil.which("yowasp-yosys")


def yosys(script, name):
    f = WORK / f"{name}.ys"
    f.write_text(script)
    p = subprocess.run([YOSYS, "-s", f"work/{f.name}"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"Yosys failed on {name}:\n{p.stdout[-1500:]}\n{p.stderr[-800:]}")
    return p.stdout


def rd(files):
    return "read_verilog -sv " + " ".join(f"rtl/{f}" for f in files) + "\n"


def synth_and_prove(design, tech):
    """Synthesise with ABC onto the real library AND prove netlist == RTL with a SAT miter."""
    top, files = DESIGNS[design]
    lib = f"libs/{tech['key']}.lib"
    stat = f"work/{design}_{tech['key']}.stat"
    s = (rd(files) + f"hierarchy -top {top}\nproc; flatten; memory_map; opt_clean\n"
         f"rename {top} gold\ndesign -stash gold_d\n"
         + rd(files) + f"synth -top {top} -flatten\nabc -liberty {lib}\nopt_clean\n"
         f"tee -o {stat} stat -liberty {lib}\n"
         f"write_verilog -noattr work/{design}_{tech['key']}_netlist.v\n"
         f"rename {top} gate\ndesign -stash gate_d\n"
         "design -copy-from gold_d -as gold gold\ndesign -copy-from gate_d -as gate gate\n"
         f"read_liberty -ignore_miss_func -ignore_miss_dir -ignore_miss_data_latch {lib}\n"
         "miter -equiv -flatten -make_assert gold gate miter\nhierarchy -top miter\nflatten\n"
         "sat -verify -prove-asserts miter\n")
    out = yosys(s, f"{design}_{tech['key']}")
    if "SUCCESS" not in out or "FAIL" in out:  # sat -verify also exits non-zero on a failed proof
        sys.exit(f"Equivalence check did not succeed for {design}/{tech['key']}. Yosys output tail:\n"
                 + out[-2500:])
    txt = (ROOT / stat).read_text()
    area = float(re.findall(r"Chip area for module '\\\w+': ([0-9.]+)", txt)[-1])
    cells = {m[0]: int(m[1]) for m in re.findall(r"^\s{3,}(\S+)\s+(\d+)\s*$", txt, re.M)
             if not m[0].startswith("$")}
    return area, cells


def eval_values(out, name):
    """Yosys prints eval results as W'bits or (for small values) as a decimal integer."""
    vals = []
    for b, d in re.findall(rf"\\{name} = (?:\d+'([01]+)|(\d+))\.", out):
        vals.append(int(b, 2) if b else int(d))
    return vals


def check_rtl_vs_python():
    """Drive the RTL with Yosys `eval` and compare with the Python reference."""
    s = rd(["present_sbox.v", "present_sbox_hand.v"]) + \
        "hierarchy -top present_sbox\nproc; flatten; memory_map; opt_clean\n"
    s += "".join(f"eval -set x 4'h{v:X} -show y\n" for v in range(16))
    out = yosys(s, "chk_sbox")
    got = eval_values(out, "y")
    assert got == SBOX, "RTL S-box differs from reference"
    rnd = random.Random(1)
    vecs = [(rnd.getrandbits(64), rnd.getrandbits(64)) for _ in range(20)]
    s = rd(["present_sbox.v", "present_round.v"]) + \
        "hierarchy -top present_round\nproc; flatten; memory_map; opt_clean\n"
    s += "".join(f"eval -set state_in 64'h{a:016x} -set round_key 64'h{k:016x} -show state_out\n"
                 for a, k in vecs)
    out = yosys(s, "chk_round")
    got = eval_values(out, "state_out")
    assert got == [present_round_ref(a, k) for a, k in vecs], "RTL round differs from reference"
    s = rd(["xor_rot32.v"]) + "hierarchy -top xor_rot32\nproc; flatten; opt_clean\n"
    xv = [(rnd.getrandbits(32), rnd.getrandbits(32)) for _ in range(10)]
    s += "".join(f"eval -set a 32'h{a:08x} -set b 32'h{b:08x} -show y\n" for a, b in xv)
    out = yosys(s, "chk_xor")
    got = eval_values(out, "y")
    rotl7 = lambda v: ((v << 7) | (v >> 25)) & 0xFFFFFFFF
    assert got == [rotl7(a ^ b) for a, b in xv], "RTL xor_rot32 differs from reference"
    # hand-built netlist == truth-table S-box, formally
    s = (rd(["present_sbox.v", "present_sbox_hand.v"]) +
         "hierarchy -top present_sbox\nproc; flatten; memory_map; opt_clean\nrename present_sbox gold\n"
         "design -stash g\nread_verilog -sv rtl/present_sbox_hand.v\nhierarchy -top present_sbox_hand\n"
         "proc; flatten; opt_clean\nrename present_sbox_hand gate\ndesign -stash h\n"
         "design -copy-from g -as gold gold\ndesign -copy-from h -as gate gate\n"
         "miter -equiv -flatten -make_assert gold gate m\nhierarchy -top m\nflatten\n"
         "sat -verify -prove-asserts m\n")
    assert "SUCCESS" in yosys(s, "chk_hand")
    print("[ok] RTL matches the Python reference (S-box x16, round x20, xor_rot x10); "
          "hand netlist formally equals the S-box")


# --------------------------------------------------------------------------- #
# 5. Main flow
# --------------------------------------------------------------------------- #
def main():
    if not YOSYS:
        sys.exit("Yosys not found. Install it (Linux: apt install yosys | Windows: "
                 "pip install yowasp-yosys) and rerun.")
    print(f"Yosys: {YOSYS}")
    check_reference()
    check_hand()
    write_rtl()
    check_rtl_vs_python()

    info = {t["key"]: tech_info(t) for t in TECHS}
    print("\nCell weights in GE (cell area / NAND2 area), read from the .lib files:")
    print(f"{'technology':<24}{'NAND2 um2':>10}" + "".join(f"{f:>7}" for f in FUNCS))
    for t in TECHS:
        i = info[t["key"]]
        print(f"{t['label']:<24}{i['nand']:>10.4f}" + "".join(f"{i['ratio'][f]:>7.2f}" for f in FUNCS))

    # hand counts: textbook weights, and structure-aware weights per library
    hc = hand_counts()
    sb_text = hand_ge(TEXTBOOK)
    hand = {"present_sbox": sb_text, "xor_rot32": 32 * TEXTBOOK["XOR2"],
            "present_round": 64 * TEXTBOOK["XOR2"] + 16 * sb_text}
    print(f"\nHand count (textbook weights INV .67, NAND/NOR 1, AND/OR 1.33, XOR 2): "
          f"S-box {sum(hc.values())} gates {hc} = {sb_text:.2f} GE")

    rows = []
    for d in DESIGNS:
        for t in TECHS:
            area, cells = synth_and_prove(d, t)
            nand = info[t["key"]]["nand"]
            rows.append(dict(design=d, tech=t["label"], tech_key=t["key"], nm=t["nm"],
                             nand2_um2=nand, area_um2=round(area, 3), GE=round(area / nand, 2),
                             n_cells=sum(cells.values()), cells=";".join(f"{k}:{v}" for k, v in sorted(cells.items()))))
            print(f"  {d:14} {t['label']:24} area {area:10.2f} um2  = {area/nand:7.2f} GE  "
                  f"({sum(cells.values())} cells)  [netlist == RTL: proven]")

    with open(OUT / "results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    with open(OUT / "cell_weights.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tech", "NAND2_um2"] + FUNCS)
        for t in TECHS:
            i = info[t["key"]]
            w.writerow([t["label"], i["nand"]] + [round(i["ratio"][x], 2) for x in FUNCS])
    with open(OUT / "hand_count.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["design", "hand_GE_textbook"])
        for k, v in hand.items():
            w.writerow([k, round(v, 2)])

    summary(rows, hand, info)
    plot(rows, hand, info)


def summary(rows, hand, info):
    g = {(r["design"], r["tech_key"]): r["GE"] for r in rows}
    print("\n=== GE summary (hand count | 45 nm | 130 nm | 180 nm) ===")
    for d in ["xor_rot32", "present_sbox", "present_round", "aes_sbox"]:
        h = f"{hand[d]:7.1f}" if d in hand else "      -"
        print(f"{LABEL[d]:<24}{h} |" + "".join(f"{g[(d, t['key'])]:8.1f}" for t in TECHS))
    print("\nExercise-4 style scaling (same GE, different NAND2 area):")
    ge = g[("present_sbox", "nangate45")]
    for n in (1.5, 0.5):
        print(f"  PRESENT S-box {ge:.1f} GE with NAND2 = {n} um2 -> {ge*n:.1f} um2")


def plot(rows, hand, info):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    designs = ["present_sbox", "xor_rot32", "present_round", "aes_sbox"]
    colors = ["#2b6cb0", "#dd6b20", "#2f855a"]
    x = np.arange(len(designs))
    w = 0.26
    fig, ax = plt.subplots(1, 3, figsize=(17, 5.4))
    for k, t in enumerate(TECHS):
        a = [next(r["area_um2"] for r in rows if r["design"] == d and r["tech_key"] == t["key"]) for d in designs]
        g = [next(r["GE"] for r in rows if r["design"] == d and r["tech_key"] == t["key"]) for d in designs]
        b1 = ax[0].bar(x + (k - 1) * w, a, w, color=colors[k], label=t["label"])
        b2 = ax[1].bar(x + (k - 1) * w, g, w, color=colors[k], label=t["label"])
        ax[1].bar_label(b2, fmt="%.0f", fontsize=7, padding=1)
    ax[1].scatter([x[i] for i, d in enumerate(designs) if d in hand],
                  [hand[d] for d in designs if d in hand], marker="D", color="black", zorder=5,
                  label="hand count (textbook weights)")
    ax[1].axhline(2000, color="red", ls="--", lw=1)
    ax[1].text(len(designs) - 0.55, 2150, "RFID security budget (2000 GE)", color="red", ha="right", fontsize=8)
    for a_, tt, yl in ((ax[0], "A. Physical area (um2): 45 nm -> 180 nm is ~16x", "um2 (log)"),
                       (ax[1], "B. Same RTL, same flow: GE per technology", "GE (log)")):
        a_.set_yscale("log")
        a_.set_xticks(x)
        a_.set_xticklabels([LABEL[d].replace(" (", "\n(") for d in designs], fontsize=8)
        a_.set_title(tt, fontsize=10)
        a_.set_ylabel(yl)
        a_.grid(axis="y", ls=":", alpha=.5)
    ax[1].set_ylim(10, 5000)
    ax[0].legend(fontsize=8)
    ax[1].legend(fontsize=7, loc="upper left")
    # panel C: why - GE weight of basic cells per library
    cells = ["INV", "AND2", "OR2", "XOR2", "DFF"]
    xc = np.arange(len(cells))
    for k, t in enumerate(TECHS):
        v = [info[t["key"]]["ratio"][c] for c in cells]
        b = ax[2].bar(xc + (k - 1) * w, v, w, color=colors[k], label=t["label"])
        ax[2].bar_label(b, fmt="%.2f", fontsize=7, padding=1)
    ax[2].axhline(1, color="gray", ls=":", lw=1)
    ax[2].set_xticks(xc)
    ax[2].set_xticklabels(cells)
    ax[2].set_ylabel("cell area / NAND2 area (GE)")
    ax[2].set_title("C. Why: a cell's GE weight changes with the library", fontsize=10)
    ax[2].legend(fontsize=8)
    ax[2].grid(axis="y", ls=":", alpha=.5)
    plt.tight_layout()
    plt.savefig(OUT / "project2_chart.png", dpi=170)
    print(f"\nSaved: {OUT/'results.csv'}, cell_weights.csv, hand_count.csv, project2_chart.png")


if __name__ == "__main__":
    main()
