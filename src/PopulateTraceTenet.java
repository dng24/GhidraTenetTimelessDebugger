//Import a Tenet trace into the debugger
//@author Derek Ng
//@category 
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Scanner;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.database.UndoableTransaction;

/**
 * Takes a Tenet trace and populates it in ghidra's trace viewer. Code inspired
 * by {@link PopulateDemoTrace} and this Qira tracer:
 * https://github.com/Tim---/ghidra-qira-traceloader/blob/master/PopulateTraceQiraCompatible.java.
 * 
 * @author derek
 *
 */
public class PopulateTraceTenet extends GhidraScript {

	private Trace trace;
	private Language lang;
	private AddressSpace addressSpace;
	private ByteBuffer buf;
	private TraceMemoryManager memory;
	private TraceMemoryRegisterSpace regs;

	@Override
	protected void run() throws Exception {
		// make sure user has the program they want to analyze open
		boolean isProgOpen = askYesNo("Program check", "Is the program you want to analyze open in debugger view?");
		if (!isProgOpen) {
			popup("Please open the program you want to analyze in debugger view.");
			return;
		}
		// open trace file
		File traceFile = askFile("Choose Trace File", "Open");
		// open memory map file for trace
		File traceMemMapFile = askFile("Choose Trace Memory Map File", "Open");

		monitor.setMessage("Initializing trace");

		// read second line of memory map file since those are the addresses which the
		// program was
		// actually located at when the trace was collected
		Scanner scanner = new Scanner(traceMemMapFile);
		scanner.nextLine();
		String memMap = scanner.nextLine();

		// get the first and last addressses of the program
		String[] memMapBounds = memMap.split("->")[0].split(":");
		long memMapStart = Long.parseUnsignedLong(memMapBounds[1].strip().substring(2), 16);
		long memMapEnd = Long.parseUnsignedLong(memMapBounds[2].strip().substring(2), 16);

		scanner.close();

		// init the trace
		trace = new DBTrace(currentProgram.getName() + " trace", currentProgram.getCompilerSpec(), this); // the trace
		lang = currentProgram.getLanguage();
		addressSpace = lang.getAddressFactory().getDefaultAddressSpace(); // the addresses
		Address ghidraImageBase = currentProgram.getImageBase(); // start address of ghidra version of the program
		// temporarily change all addresses in ghidra version to match the trace version
		// we do this so that we can copy instructions from the listing view (which uses
		// ghidra addresses) to the
		// dynamic view (which uses trace addresses), and have the dynamic view
		// instructions match their addresses
		currentProgram.setImageBase(toAddr(memMapStart), false);
		buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
		TraceThread thread;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			TraceSnapshot snapshot = trace.getTimeManager().createSnapshot("Launched");
			long snap = snapshot.getKey();
			thread = trace.getThreadManager().addThread("Main Thread", Range.atLeast(snap));
			memory = trace.getMemoryManager();
			regs = memory.getMemoryRegisterSpace(thread, true);

			// add text section
			memory.addRegion(".text", Range.atLeast(snap), rng(memMapStart, memMapEnd), TraceMemoryFlag.READ,
					TraceMemoryFlag.EXECUTE);
			reconstructProg(snap);
			if (monitor.isCancelled()) {
				// reset addresses in listing view back to ghidra addresses
				currentProgram.setImageBase(ghidraImageBase, false);
				return;
			}
		}

		scanner = new Scanner(traceFile);
		String assemblyInstruction = "Initialization";
		long currentPC = -1;
		monitor.setMessage("Populating trace");
		monitor.setIndeterminate(true);
		while (scanner.hasNextLine()) {
			if (monitor.isCancelled()) {
				// reset addresses in listing view back to ghidra addresses
				currentProgram.setImageBase(ghidraImageBase, false);
				scanner.close();
				return;
			}
			String line = scanner.nextLine();
			String[] regMemChanges = line.split(",");
			Address currentAddress = currentPC == -1 ? null : addr(currentPC);
			long nextPC = processInstruction(regMemChanges, assemblyInstruction, currentAddress);
			Address ghidraNextPC = toAddr(nextPC); // progBaseAddress.getAddress(Long.toHexString(nextPC));
			assemblyInstruction = currentProgram.getListing().getInstructionAt(ghidraNextPC).toString();
			currentPC = nextPC;
		}
		scanner.close();
		DebuggerTraceManagerService manager = state.getTool().getService(DebuggerTraceManagerService.class);
		manager.openTrace(trace);
		manager.activateTrace(trace);

		// reset addresses in listing view back to ghidra addresses
		currentProgram.setImageBase(ghidraImageBase, false);
	}

	/**
	 * Put together the dynamic view by taking each instruction in the listing view
	 * and placing it in the dynamic view by assembling it. Also copy over functions
	 * and labels.
	 * 
	 * @param snap
	 * @throws Exception
	 */
	void reconstructProg(long snap) throws Exception {
		Assembler asm = Assemblers.getAssembler(trace.getFixedProgramView(snap));

		// take each instrucion in the listing view and copy it to the dynamic view via
		// the assembler
		Instruction currentInstr = getFirstInstruction();
		int i = 0;
		monitor.setMessage("Creating dynamic view");
		while (currentInstr != null) {
			if (monitor.isCancelled()) {
				return;
			}
			try {
				asm.assemble(addr(currentInstr.getAddress().getOffset()), currentInstr.toString());
			} catch (AssemblySyntaxException e) {
				System.out.println("Unable to assemble instruction number " + i + ": " + currentInstr.toString());
			}
			currentInstr = getInstructionAfter(currentInstr);
			i++;
		}

		// copy over functions and labels from listing view to dynamic view
		Function currentFunc = getFirstFunction();
		while (currentFunc != null) {
			createFunction(addr(currentFunc.getEntryPoint().getOffset()), currentFunc.getName());
			trace.getSymbolManager().labels().create(snap, null, addr(currentFunc.getEntryPoint().getOffset()),
					currentFunc.getName(), trace.getSymbolManager().getGlobalNamespace(), SourceType.USER_DEFINED);
			currentFunc = getFunctionAfter(currentFunc);
		}
	}

	/**
	 * Take a line of the trace and make a ghidra snapshot out of it.
	 * 
	 * @param regMemChanges       a line of tenet trace
	 * @param assemblyInstruction assembly instruction as a string
	 * @param realInstrAddress    trace address of current instruction
	 * @return address of next instruction (the rip field in regMemChanges)
	 * @throws AssemblySyntaxException
	 * @throws AssemblySemanticException
	 * @throws MemoryAccessException
	 * @throws AddressOverflowException
	 */
	long processInstruction(String[] regMemChanges, String assemblyInstruction, Address realInstrAddress)
			throws AssemblySyntaxException, AssemblySemanticException, MemoryAccessException, AddressOverflowException {
		long nextPC = 0;
		try (UndoableTransaction tid = UndoableTransaction.start(trace, "Step", true)) {
			// set the description to show user in ghidra trace window
			String description = "Initialization";
			if (realInstrAddress != null) {
				description = "0x" + realInstrAddress + ": " + assemblyInstruction;
			}
			long snap = trace.getTimeManager().createSnapshot(description).getKey();
			for (String regMemChange : regMemChanges) {
				// parse line of trace to get regs/mem and values
				String[] regMemNameVal = regMemChange.split("=");
				String regMemName = regMemNameVal[0];
				String regMemVal = regMemNameVal[1];
				if (regMemName.equals("mr") || regMemName.equals("mw") || regMemName.equals("mrw")) {
					// memory access
					String[] addressVal = regMemVal.split(":");
					String address = addressVal[0];
					String val = addressVal[1];
					memory.putBytes(snap, addressSpace.getAddress(Long.decode(address)),
							buf.clear().putLong(Long.parseUnsignedLong(val, 16)).flip());

				} else {
					// register change
					Register reg = lang.getRegister(regMemName);
					long regVal = Long.parseUnsignedLong(regMemVal.substring(2), 16);

					if (reg.isProgramCounter()) {
						nextPC = regVal;
						long pcVal = realInstrAddress == null ? 0 : realInstrAddress.getOffset();
						regs.putBytes(snap, reg, buf.clear().putLong(pcVal).flip());
					} else {
						regs.putBytes(snap, reg, buf.clear().putLong(regVal).flip());
					}

				}
			}
		}
		return nextPC;
	}

	/**
	 * Create an address in the processor's (x86_64) default space.
	 * 
	 * @param offset the byte offset
	 * @return the address
	 */
	protected Address addr(long offset) {
		return addressSpace.getAddress(offset);
	}

	/**
	 * Create an address range in the processor's default space.
	 * 
	 * @param min the minimum byte offset
	 * @param max the maximum (inclusive) byte offset
	 * @return the range
	 */
	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

}
