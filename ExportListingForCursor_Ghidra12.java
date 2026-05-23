// ExportListingForCursor_Ghidra12.java
// Compatible target: Ghidra 12.0.x
//
// Purpose:
//   Export function-by-function Listing/assembly for Cursor analysis.
//   No decompiler is used.
//   Uses conservative Ghidra APIs to avoid compile errors.
//
// Output:
//   asm/
//     <address>_<function_name>.asm
//   indexes/
//     all_functions.csv
//     all_symbols.csv
//     all_references.csv
//     function_calls.csv
//     function_data_refs.csv
//   comments/
//     all_comments.csv
//   strings/
//     defined_strings.csv
//   README_EXPORT.md

import ghidra.app.script.GhidraScript;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;

import ghidra.program.model.data.DataType;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

public class ExportListingForCursor_Ghidra12 extends GhidraScript {

    private File rootDir;

    private PrintWriter functionsCsv;
    private PrintWriter symbolsCsv;
    private PrintWriter refsCsv;
    private PrintWriter callsCsv;
    private PrintWriter dataRefsCsv;
    private PrintWriter commentsCsv;
    private PrintWriter stringsCsv;

    private String csv(String s) {
        if (s == null) {
            s = "";
        }
        s = s.replace("\"", "\"\"");
        return "\"" + s + "\"";
    }

    private String safeName(String s) {
        if (s == null || s.length() == 0) {
            s = "unnamed";
        }
        s = s.replaceAll("[\\\\/:*?\"<>|\\s]+", "_");
        if (s.length() > 120) {
            s = s.substring(0, 120);
        }
        return s;
    }

    private void mkdir(String name) {
        File d = new File(rootDir, name);
        if (!d.exists()) {
            d.mkdirs();
        }
    }

    private PrintWriter openWriter(File f) throws Exception {
        return new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), "UTF-8"));
    }

    private void writeText(File f, String text) throws Exception {
        PrintWriter pw = openWriter(f);
        try {
            pw.print(text);
        }
        finally {
            pw.close();
        }
    }

    private void initCsv() throws Exception {
        functionsCsv = openWriter(new File(rootDir, "indexes/all_functions.csv"));
        functionsCsv.println("entry,name,namespace,signature,body_start,body_end,is_thunk,comment");

        symbolsCsv = openWriter(new File(rootDir, "indexes/all_symbols.csv"));
        symbolsCsv.println("address,name,symbol_type,namespace,source,is_primary");

        refsCsv = openWriter(new File(rootDir, "indexes/all_references.csv"));
        refsCsv.println("from,to,ref_type,operand_index,is_primary");

        callsCsv = openWriter(new File(rootDir, "indexes/function_calls.csv"));
        callsCsv.println("caller_entry,caller_name,callsite,callee,callee_function");

        dataRefsCsv = openWriter(new File(rootDir, "indexes/function_data_refs.csv"));
        dataRefsCsv.println("function_entry,function_name,from,to,ref_type,target_symbol");

        commentsCsv = openWriter(new File(rootDir, "comments/all_comments.csv"));
        commentsCsv.println("address,comment_type,comment");

        stringsCsv = openWriter(new File(rootDir, "strings/defined_strings.csv"));
        stringsCsv.println("address,length,string");
    }

    private void closeCsv() {
        PrintWriter[] arr = {
            functionsCsv, symbolsCsv, refsCsv, callsCsv,
            dataRefsCsv, commentsCsv, stringsCsv
        };

        for (int i = 0; i < arr.length; i++) {
            if (arr[i] != null) {
                arr[i].close();
            }
        }
    }

    private String getComment(CodeUnit cu, int type) {
        try {
            String c = cu.getComment(type);
            if (c == null) {
                return "";
            }
            return c.replace("\r", " ").replace("\n", " | ");
        }
        catch (Exception e) {
            return "";
        }
    }

    private void exportFunctionListing(
            Function func,
            Listing listing,
            SymbolTable symtab,
            ReferenceManager refman,
            FunctionManager fm) throws Exception {

        Address entry = func.getEntryPoint();
        String name = func.getName();
        String namespace = func.getParentNamespace().getName(true);
        String sig = func.getSignature().toString();
        AddressSetView body = func.getBody();
        Address bodyStart = body.getMinAddress();
        Address bodyEnd = body.getMaxAddress();
        String fcomment = func.getComment();

        functionsCsv.println(
            csv(entry.toString()) + "," +
            csv(name) + "," +
            csv(namespace) + "," +
            csv(sig) + "," +
            csv(bodyStart == null ? "" : bodyStart.toString()) + "," +
            csv(bodyEnd == null ? "" : bodyEnd.toString()) + "," +
            csv(Boolean.toString(func.isThunk())) + "," +
            csv(fcomment)
        );

        String fileName = entry.toString() + "_" + safeName(name) + ".asm";
        File outFile = new File(rootDir, "asm/" + fileName);

        StringBuilder out = new StringBuilder();

        out.append("; ENTRY: ").append(entry).append("\n");
        out.append("; NAME: ").append(name).append("\n");
        out.append("; NAMESPACE: ").append(namespace).append("\n");
        out.append("; SIGNATURE: ").append(sig).append("\n");
        out.append("; BODY: ").append(bodyStart).append(" - ").append(bodyEnd).append("\n");
        if (fcomment != null && fcomment.length() > 0) {
            out.append("; FUNCTION_COMMENT: ").append(fcomment.replace("\r", " ").replace("\n", " | ")).append("\n");
        }
        out.append("\n");

        CodeUnitIterator it = listing.getCodeUnits(body, true);

        while (it.hasNext() && !monitor.isCancelled()) {
            CodeUnit cu = it.next();
            Address a = cu.getAddress();

            Symbol primary = symtab.getPrimarySymbol(a);
            if (primary != null && primary.getAddress().equals(a)) {
                out.append("\n").append(primary.getName(true)).append(":\n");
            }

            String plate = getComment(cu, CodeUnit.PLATE_COMMENT);
            String pre = getComment(cu, CodeUnit.PRE_COMMENT);
            String repeat = getComment(cu, CodeUnit.REPEATABLE_COMMENT);

            if (plate.length() > 0) {
                out.append("; PLATE: ").append(plate).append("\n");
            }
            if (pre.length() > 0) {
                out.append("; PRE: ").append(pre).append("\n");
            }
            if (repeat.length() > 0) {
                out.append("; REPEATABLE: ").append(repeat).append("\n");
            }

            String eol = getComment(cu, CodeUnit.EOL_COMMENT);
            String post = getComment(cu, CodeUnit.POST_COMMENT);

            if (cu instanceof Instruction) {
                Instruction ins = (Instruction) cu;

                // Conservative output for Ghidra 12:
                // ins.toString() includes mnemonic and operands.
                out.append(a.toString())
                   .append("  ")
                   .append(ins.toString());

                if (eol.length() > 0) {
                    out.append(" ; ").append(eol);
                }
                out.append("\n");

                if (post.length() > 0) {
                    out.append("; POST: ").append(post).append("\n");
                }

                Reference[] refs = refman.getReferencesFrom(a);
                for (int i = 0; i < refs.length; i++) {
                    Reference r = refs[i];
                    Address to = r.getToAddress();
                    String refType = r.getReferenceType().toString();

                    refsCsv.println(
                        csv(a.toString()) + "," +
                        csv(to == null ? "" : to.toString()) + "," +
                        csv(refType) + "," +
                        csv(Integer.toString(r.getOperandIndex())) + "," +
                        csv(Boolean.toString(r.isPrimary()))
                    );

                    if (r.getReferenceType().isCall()) {
                        Function callee = null;
                        if (to != null) {
                            callee = fm.getFunctionAt(to);
                        }
                        callsCsv.println(
                            csv(entry.toString()) + "," +
                            csv(name) + "," +
                            csv(a.toString()) + "," +
                            csv(to == null ? "" : to.toString()) + "," +
                            csv(callee == null ? "" : callee.getName())
                        );
                    }
                    else if (r.getReferenceType().isData()) {
                        Symbol targetSymbol = null;
                        if (to != null) {
                            targetSymbol = symtab.getPrimarySymbol(to);
                        }
                        dataRefsCsv.println(
                            csv(entry.toString()) + "," +
                            csv(name) + "," +
                            csv(a.toString()) + "," +
                            csv(to == null ? "" : to.toString()) + "," +
                            csv(refType) + "," +
                            csv(targetSymbol == null ? "" : targetSymbol.getName(true))
                        );
                    }
                }
            }
            else if (cu instanceof Data) {
                Data d = (Data) cu;
                Object val = null;
                try {
                    val = d.getValue();
                }
                catch (Exception ignored) {}

                out.append(a.toString())
                   .append("  DATA  ")
                   .append(d.getDataType().getName())
                   .append("  ")
                   .append(val == null ? "" : val.toString());

                if (eol.length() > 0) {
                    out.append(" ; ").append(eol);
                }
                out.append("\n");

                if (post.length() > 0) {
                    out.append("; POST: ").append(post).append("\n");
                }
            }
            else {
                out.append(a.toString()).append("  ").append(cu.toString()).append("\n");
            }
        }

        writeText(outFile, out.toString());
    }

    private void exportSymbols(SymbolTable symtab) {
        SymbolIterator it = symtab.getAllSymbols(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Symbol s = it.next();
            try {
                symbolsCsv.println(
                    csv(s.getAddress() == null ? "" : s.getAddress().toString()) + "," +
                    csv(s.getName()) + "," +
                    csv(s.getSymbolType().toString()) + "," +
                    csv(s.getParentNamespace().getName(true)) + "," +
                    csv(s.getSource().toString()) + "," +
                    csv(Boolean.toString(s.isPrimary()))
                );
            }
            catch (Exception ignored) {}
        }
    }

    private void exportComments(Listing listing) {
        int[] types = {
            CodeUnit.EOL_COMMENT,
            CodeUnit.PRE_COMMENT,
            CodeUnit.POST_COMMENT,
            CodeUnit.PLATE_COMMENT,
            CodeUnit.REPEATABLE_COMMENT
        };

        String[] names = {
            "EOL",
            "PRE",
            "POST",
            "PLATE",
            "REPEATABLE"
        };

        AddressIterator ait = listing.getCommentAddressIterator(currentProgram.getMemory(), true);
        while (ait.hasNext() && !monitor.isCancelled()) {
            Address a = ait.next();
            CodeUnit cu = listing.getCodeUnitAt(a);
            if (cu == null) {
                continue;
            }

            for (int i = 0; i < types.length; i++) {
                String c = getComment(cu, types[i]);
                if (c.length() > 0) {
                    commentsCsv.println(csv(a.toString()) + "," + csv(names[i]) + "," + csv(c));
                }
            }
        }
    }

    private void exportStrings(Listing listing) {
        DataIterator dit = listing.getDefinedData(true);
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            try {
                DataType dt = d.getDataType();
                String dtName = dt.getName().toLowerCase();

                if (dtName.contains("string") || dtName.contains("unicode")) {
                    Object val = d.getValue();
                    if (val != null) {
                        stringsCsv.println(
                            csv(d.getAddress().toString()) + "," +
                            csv(Integer.toString(d.getLength())) + "," +
                            csv(val.toString())
                        );
                    }
                }
            }
            catch (Exception ignored) {}
        }
    }

    @Override
    public void run() throws Exception {
        rootDir = askDirectory("Choose Cursor listing export directory", "Export");

        mkdir("asm");
        mkdir("indexes");
        mkdir("comments");
        mkdir("strings");

        initCsv();

        FunctionManager fm = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        SymbolTable symtab = currentProgram.getSymbolTable();
        ReferenceManager refman = currentProgram.getReferenceManager();

        int count = 0;
        FunctionIterator fit = fm.getFunctions(true);

        while (fit.hasNext() && !monitor.isCancelled()) {
            Function func = fit.next();
            exportFunctionListing(func, listing, symtab, refman, fm);

            count++;
            if ((count % 100) == 0) {
                println("Exported listing functions: " + count);
            }
        }

        println("Exporting symbols...");
        exportSymbols(symtab);

        println("Exporting comments...");
        exportComments(listing);

        println("Exporting strings...");
        exportStrings(listing);

        writeText(new File(rootDir, "README_EXPORT.md"),
            "# Ghidra Cursor Listing Export\n\n" +
            "Ghidra version target: 12.0.x\n\n" +
            "This export uses Listing/assembly, not decompiler C.\n\n" +
            "Read order:\n" +
            "1. indexes/all_functions.csv\n" +
            "2. indexes/all_symbols.csv\n" +
            "3. comments/all_comments.csv\n" +
            "4. strings/defined_strings.csv\n" +
            "5. indexes/function_calls.csv\n" +
            "6. indexes/function_data_refs.csv\n" +
            "7. asm/<function>.asm\n\n" +
            "Do not reconstruct full C/C++ source.\n"
        );

        closeCsv();

        println("Listing export complete: " + rootDir.getAbsolutePath());
    }
}
