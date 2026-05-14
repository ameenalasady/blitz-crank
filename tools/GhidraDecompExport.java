// GhidraDecompExport — Ghidra headless analysis script
// ======================================================
// Exports a comprehensive binary analysis bundle from a loaded Ghidra program:
//
//   metadata.json     — binary name, arch, image base, function/symbol counts
//   imports.txt       — external symbol table (DLL imports)
//   exports.txt       — exported entry points (N-API symbols, DllMain, etc.)
//   strings.txt       — all defined string literals with addresses
//   functions.txt     — function list with address, size, signature, calling convention
//   decompiled_all.c  — full decompiled pseudocode (all functions, concatenated)
//   functions/        — per-function .c files for targeted analysis
//   xrefs.txt         — call graph (caller → callee cross-reference map)
//   datatypes.txt     — structs, enums, and typedefs recovered by Ghidra
//   segments.txt      — PE/ELF memory segments with permissions
//
// Usage (headless):
//
//   analyzeHeadless <project_dir> <project_name>  \
//     -import <binary>                             \
//     -postScript GhidraDecompExport.java [output_dir] \
//     -processor x86:LE:64:default                \
//     -cspec windows
//
// If [output_dir] is omitted, output lands in <cwd>/ghidra_export/.
//
// @category Analysis
// @author blitz-crank

import java.io.*;
import java.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.block.*;
import ghidra.program.util.*;
import ghidra.util.task.TaskMonitor;

public class GhidraDecompExport extends GhidraScript {

    private File outputDir;

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0) {
            outputDir = new File(args[0]);
        } else {
            outputDir = new File(System.getProperty("user.dir"), "ghidra_export");
        }
        outputDir.mkdirs();

        println("╔══════════════════════════════════════════╗");
        println("║  GhidraDecompExport                      ║");
        println("╚══════════════════════════════════════════╝");
        println("[*] Binary    : " + currentProgram.getName());
        println("[*] Arch      : " + currentProgram.getLanguage().getProcessor()
                + "  (" + currentProgram.getLanguageID() + ")");
        println("[*] Compiler  : " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("[*] Image base: " + currentProgram.getImageBase());
        println("[*] Output    : " + outputDir.getAbsolutePath());
        println("");

        exportMetadata();
        exportImports();
        exportExports();
        exportStrings();
        exportFunctionList();
        exportDecompiledCode();
        exportXrefs();
        exportDataTypes();
        exportSegments();

        println("");
        println("[✓] Export complete → " + outputDir.getAbsolutePath());
    }

    // ── Metadata ──────────────────────────────────────────────────────────────
    private void exportMetadata() throws Exception {
        File f = new File(outputDir, "metadata.json");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            FunctionManager fm = currentProgram.getFunctionManager();
            SymbolTable st = currentProgram.getSymbolTable();

            w.println("{");
            w.println("  \"name\": \""         + esc(currentProgram.getName()) + "\",");
            w.println("  \"format\": \""       + esc(currentProgram.getExecutableFormat()) + "\",");
            w.println("  \"language\": \""     + esc(currentProgram.getLanguageID().toString()) + "\",");
            w.println("  \"compiler\": \""     + esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",");
            w.println("  \"processor\": \""    + esc(currentProgram.getLanguage().getProcessor().toString()) + "\",");
            w.println("  \"addressSize\": "    + currentProgram.getDefaultPointerSize() + ",");
            w.println("  \"imageBase\": \""    + currentProgram.getImageBase().toString() + "\",");
            w.println("  \"executablePath\": \"" + esc(currentProgram.getExecutablePath()) + "\",");
            w.println("  \"functionCount\": " + fm.getFunctionCount() + ",");
            w.println("  \"symbolCount\": "   + st.getNumSymbols() + ",");
            w.println("  \"exportedAt\": \""  + new java.util.Date().toString() + "\"");
            w.println("}");
        }
        println("[+] metadata.json");
    }

    // ── Imports ───────────────────────────────────────────────────────────────
    // DLL imports resolved by Ghidra's PE loader. Each entry is the external
    // stub symbol that acts as a thunk for the real Windows API call.
    private void exportImports() throws Exception {
        File f = new File(outputDir, "imports.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Imported symbols (DLL imports)");
            w.println("# Format: ADDRESS | LIBRARY | NAME");
            w.println("#");

            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getExternalSymbols();
            int count = 0;
            while (it.hasNext()) {
                Symbol sym = it.next();
                ExternalLocation ext = currentProgram.getExternalManager()
                    .getExternalLocation(sym);
                String lib = (ext != null && ext.getLibraryName() != null)
                    ? ext.getLibraryName() : "<unknown>";
                w.printf("%s | %s | %s%n",
                    sym.getAddress().toString(), lib, sym.getName());
                count++;
            }
            println("[+] imports.txt  (" + count + " symbols)");
        }
    }

    // ── Exports ───────────────────────────────────────────────────────────────
    // For Node.js native addons (.node files), these are the N-API entry points
    // (napi_register_module_v1, etc.) that Node.js resolves at require() time.
    private void exportExports() throws Exception {
        File f = new File(outputDir, "exports.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Exported symbols (entry points)");
            w.println("# Format: ADDRESS | NAME | TYPE");
            w.println("#");

            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator it = st.getAllSymbols(true);
            int count = 0;
            while (it.hasNext()) {
                Symbol sym = it.next();
                if (sym.isExternalEntryPoint()) {
                    w.printf("%s | %s | %s%n",
                        sym.getAddress().toString(),
                        sym.getName(),
                        sym.getSymbolType().toString());
                    count++;
                }
            }
            println("[+] exports.txt  (" + count + " symbols)");
        }
    }

    // ── Strings ───────────────────────────────────────────────────────────────
    // Defined string literals are the fastest way to find error codes, URLs,
    // log prefixes, and registry paths without reading disassembly.
    private void exportStrings() throws Exception {
        File f = new File(outputDir, "strings.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Defined string literals");
            w.println("# Format: ADDRESS | LENGTH | VALUE");
            w.println("#");

            DataIterator it = currentProgram.getListing().getDefinedData(true);
            int count = 0;
            while (it.hasNext()) {
                Data data = it.next();
                if (data.hasStringValue()) {
                    w.printf("%s | %d | %s%n",
                        data.getAddress().toString(),
                        data.getLength(),
                        data.getDefaultValueRepresentation());
                    count++;
                }
            }
            println("[+] strings.txt  (" + count + " strings)");
        }
    }

    // ── Function List ─────────────────────────────────────────────────────────
    // Quick index: address, byte size, name, full prototype, calling convention.
    // Use this to locate a function by name before loading decompiled_all.c.
    private void exportFunctionList() throws Exception {
        File f = new File(outputDir, "functions.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Function list");
            w.println("# Format: ADDRESS | SIZE_BYTES | NAME | SIGNATURE | CALLING_CONVENTION");
            w.println("#");

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (it.hasNext()) {
                Function func = it.next();
                w.printf("%s | %d | %s | %s | %s%n",
                    func.getEntryPoint().toString(),
                    func.getBody().getNumAddresses(),
                    func.getName(),
                    func.getSignature().getPrototypeString(),
                    func.getCallingConventionName());
                count++;
            }
            println("[+] functions.txt  (" + count + " functions)");
        }
    }

    // ── Decompiled Code ───────────────────────────────────────────────────────
    // Two outputs:
    //   decompiled_all.c — single concatenated file (ideal for AI/grep)
    //   functions/       — one file per function (ideal for targeted review)
    //
    // The decompiler timeout per function is 30 seconds. Functions that time
    // out or fail are noted with a [FAILED] comment.
    private void exportDecompiledCode() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(false);
        decomp.setSimplificationStyle("decompile");

        if (!decomp.openProgram(currentProgram)) {
            printerr("Decompiler failed to open: " + decomp.getLastMessage());
            return;
        }

        File allFile    = new File(outputDir, "decompiled_all.c");
        File perFuncDir = new File(outputDir, "functions");
        perFuncDir.mkdirs();

        int total  = currentProgram.getFunctionManager().getFunctionCount();
        int count  = 0;
        int failed = 0;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);

        try (PrintWriter allWriter = new PrintWriter(new FileWriter(allFile))) {
            allWriter.println("// ═══════════════════════════════════════════════════════════════");
            allWriter.println("// GhidraDecompExport — " + currentProgram.getName());
            allWriter.println("// Functions : " + total);
            allWriter.println("// Generated : " + new java.util.Date().toString());
            allWriter.println("// ═══════════════════════════════════════════════════════════════");
            allWriter.println();

            while (it.hasNext()) {
                Function func = it.next();
                count++;

                if (count % 100 == 0) {
                    println("[*] Decompiling " + count + " / " + total + " ...");
                }

                DecompileResults res = decomp.decompileFunction(func, 30, monitor);

                if (res == null || !res.decompileCompleted()) {
                    failed++;
                    allWriter.println("// [FAILED] " + func.getName()
                        + " @ " + func.getEntryPoint());
                    allWriter.println();
                    continue;
                }

                DecompiledFunction df = res.getDecompiledFunction();
                if (df == null) { failed++; continue; }

                String body = df.getC();

                // Combined file
                allWriter.println("// ─────────────────────────────────────────────────────────────");
                allWriter.printf("// %s  @  %s  (%d bytes)%n",
                    func.getName(),
                    func.getEntryPoint(),
                    func.getBody().getNumAddresses());
                allWriter.println("// ─────────────────────────────────────────────────────────────");
                allWriter.println(body);
                allWriter.println();

                // Per-function file
                String safeName = func.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                String fileName = String.format("%s_%s.c",
                    func.getEntryPoint().toString().replace(":", "_"), safeName);
                try (PrintWriter fw = new PrintWriter(
                        new FileWriter(new File(perFuncDir, fileName)))) {
                    fw.printf("// Function : %s%n", func.getName());
                    fw.printf("// Address  : %s%n", func.getEntryPoint());
                    fw.printf("// Size     : %d bytes%n", func.getBody().getNumAddresses());
                    fw.printf("// Convention: %s%n", func.getCallingConventionName());
                    fw.println();
                    fw.println(body);
                }
            }
        }

        decomp.dispose();
        println("[+] decompiled_all.c  (" + count + " functions, " + failed + " failed)");
        println("[+] functions/        (" + (count - failed) + " individual files)");
    }

    // ── Cross-references ──────────────────────────────────────────────────────
    // Call graph: which functions call which. Use this to trace execution paths
    // from a known string (e.g. "E6 Error") back to the root integrity loop.
    private void exportXrefs() throws Exception {
        File f = new File(outputDir, "xrefs.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Cross-references (call graph)");
            w.println("# Format: CALLER_ADDR | CALLER_NAME -> CALLEE_ADDR | CALLEE_NAME");
            w.println("#");

            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            int count = 0;
            while (it.hasNext()) {
                Function caller = it.next();
                for (Function callee : caller.getCalledFunctions(monitor)) {
                    w.printf("%s | %s -> %s | %s%n",
                        caller.getEntryPoint(), caller.getName(),
                        callee.getEntryPoint(), callee.getName());
                    count++;
                }
            }
            println("[+] xrefs.txt  (" + count + " edges)");
        }
    }

    // ── Data Types ────────────────────────────────────────────────────────────
    // Structs, enums, and typedefs recovered or inferred by Ghidra.
    // Struct layouts show field offsets — useful for identifying vtables and
    // embedded protocol buffers.
    private void exportDataTypes() throws Exception {
        File f = new File(outputDir, "datatypes.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Recovered data types (structs, enums, typedefs)");
            w.println("#");

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Iterator<DataType> it = dtm.getAllDataTypes();
            int count = 0;
            while (it.hasNext()) {
                DataType dt = it.next();
                if (dt.getDataTypeManager() != dtm) continue; // skip builtins

                String kind = dt.getClass().getSimpleName();
                w.printf("[%s] %s  (size: %d, path: %s)%n",
                    kind, dt.getName(), dt.getLength(),
                    dt.getCategoryPath().toString());

                if (dt instanceof Structure) {
                    for (DataTypeComponent comp : ((Structure) dt).getComponents()) {
                        w.printf("    +0x%04X  %-20s  %s  (%d bytes)%n",
                            comp.getOffset(),
                            comp.getDataType().getName(),
                            comp.getFieldName() != null ? comp.getFieldName() : "<anon>",
                            comp.getLength());
                    }
                } else if (dt instanceof ghidra.program.model.data.Enum) {
                    ghidra.program.model.data.Enum en = (ghidra.program.model.data.Enum) dt;
                    for (String name : en.getNames()) {
                        w.printf("    %-30s = 0x%X%n", name, en.getValue(name));
                    }
                }
                count++;
            }
            println("[+] datatypes.txt  (" + count + " types)");
        }
    }

    // ── Memory Segments ───────────────────────────────────────────────────────
    // PE sections (.text, .rdata, .data, etc.) with their virtual addresses
    // and permissions. Cross-reference against the RVA→file-offset calculation
    // in patch.py to verify your target function is in the .text section.
    private void exportSegments() throws Exception {
        File f = new File(outputDir, "segments.txt");
        try (PrintWriter w = new PrintWriter(new FileWriter(f))) {
            w.println("# Memory segments / PE sections");
            w.println("# Format: NAME | START_VA | END_VA | SIZE | PERMS");
            w.println("#");

            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                String perms = (block.isRead()    ? "R" : "-")
                             + (block.isWrite()   ? "W" : "-")
                             + (block.isExecute() ? "X" : "-");
                w.printf("%-12s | %s | %s | 0x%08X | %s%n",
                    block.getName(),
                    block.getStart().toString(),
                    block.getEnd().toString(),
                    block.getSize(),
                    perms);
            }
            println("[+] segments.txt  (" + currentProgram.getMemory().getBlocks().length + " segments)");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    /** JSON-escape a string: backslash, quote, newline. */
    private String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "");
    }
}
