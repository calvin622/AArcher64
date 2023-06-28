import angr
import capstone
import claripy

def find_gadgets_near_ret_instructions(binary_path):
    # Load the binary into an Angr project
    project = angr.Project(binary_path, auto_load_libs=False)

    # Define the entry point of the binary
    entry_point = project.loader.main_object.get_symbol("main").rebased_addr

    # Create a blank state at the entry point
    state = project.factory.blank_state(addr=entry_point)

    # Create symbolic variables to represent the return address and frame pointer
    return_address = claripy.BVS("return_address", project.arch.bits)
    frame_pointer = claripy.BVS("frame_pointer", project.arch.bits)

    # Add constraints to the return address and frame pointer
    state.add_constraints(return_address >= project.loader.main_object.min_addr)
    state.add_constraints(return_address < project.loader.main_object.max_addr)
    state.add_constraints(frame_pointer >= project.loader.main_object.min_addr)
    state.add_constraints(frame_pointer < project.loader.main_object.max_addr)

    # Store the symbolic return address in the link register (x30)
    state.regs.lr = return_address

    # Set the frame pointer (x29) to the symbolic frame pointer value
    state.regs.x29 = frame_pointer

    # Create an empty list to store the frontier of states
    frontier = [state]

    # Define the RET instructions
    ret_instructions = [
        b'\xc0\x03\x5f\xd6',
        b'\xc0\x03\x5f\xd6\x00\x00\x80\x52',
        b'\xfd{\xbe\xa9\xfd\x03\x00\x91',
        b'\x90\x00\x00\x90\x11\xdeG\xf9',
        b'\xf4\xff\xff\x97\x00\x00\x80R',
        b'\x1f \x03\xd5\xfd{\xc2\xa8',
        b'\x00\x00\x80R\xfd{\xc2\xa8'
    ]

    while frontier:
        current_state = frontier.pop()
        instruction_bytes = current_state.solver.eval(current_state.memory.load(current_state.addr, 8), cast_to=bytes)
        for ret_instruction in ret_instructions:
            if ret_instruction in instruction_bytes:
                ret_address = current_state.addr

                # Find gadgets before the RET instruction
                start_address = ret_address - 8  # Adjust this value to control the range of the gadget search

                # Disassemble the instructions in the specified range
                disassembly = project.factory.block(start_address, ret_address + 4).capstone.insns[::-1]

                gadget_instructions = []
                for insn in disassembly:
                    gadget_instructions.append(f"{insn.mnemonic} {insn.op_str}")
                    if insn.address == ret_address:
                        if len(gadget_instructions) >= 3:
                            gadget_tuple = (start_address + 12, gadget_instructions[-2], gadget_instructions[-1], gadget_instructions[0])
                            print(f"Found gadget: {hex(gadget_tuple[0])}; {gadget_tuple[1]}; {gadget_tuple[2]}; {gadget_tuple[3]}")
                        break

        successors = current_state.step()
        frontier.extend(successors.flat_successors)

if __name__ == "__main__":
    binary_path = "/home/ubuntu/AArcher64/binaries/binary"
    find_gadgets_near_ret_instructions(binary_path)
