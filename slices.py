import binaryninja
from binaryninja import *
from binaryninja.mediumlevelil import SSAVariable, MediumLevelILFunction
from Queue import Queue

def forward(instruction):
    """
    Perform a forward slice on the given instruction

    :param ILInstruction instruction: Instruction to slice on

    :return: List of instruction indexes involved in the current slice
    :rtype: list(int)
    :Example:

        >>> slices.forward(mlil[6])
    """

    function = instruction.function
    if not isinstance(function, MediumLevelILFunction):
        ssa = function.medium_level_il.ssa_form
    else:
        ssa = function.ssa_form

    if not isinstance(instruction.ssa_form.operands[0], SSAVariable):
        return set()

    operand = instruction.ssa_form.operands[0] 
    instruction_queue = set()

    instruction_queue.update(
        ssa.get_ssa_var_uses(operand)
    )

    # visited_instructions = set()
    visited_instructions = []
    visited_instructions.append(instruction.ssa_form.instr_index)

    while instruction_queue:
        visit_index = instruction_queue.pop()

        if visit_index is None or visit_index in visited_instructions:
            continue

        instruction_to_visit = ssa[visit_index]

        if instruction_to_visit is None:
            continue

        for new_var in instruction_to_visit.vars_written:
            instruction_queue.update(
                    ssa.get_ssa_var_uses(new_var)
	    )

        visited_instructions.append(visit_index)

    if len(visited_instructions) < 40:
        return [ssa[i] for i in visited_instructions]
    else:
        return []

def backward(instruction):
    """
    Assumes the instruction is a variable

    Example usage:

    for a in slices.backward(mlilssa[51].params[0]):
	print('-' * 40)
	for il in reversed(a):
	    print(il.function.source_function.name, il)
    """

    function = instruction.function
    if not isinstance(function, MediumLevelILFunction):
        ssa = function.medium_level_il.ssa_form
    else:
        ssa = function.ssa_form


    next_instr = ssa[ssa.get_ssa_var_definition(instruction.src)]

    instruction_queue = Queue()
    # instruction_queue.put([instruction.ssa_form])
    instruction_queue.put([instruction, next_instr])

    variables = set()

    results = []

    while instruction_queue.qsize() > 0:
        curr_path = instruction_queue.get()
        print(curr_path)

        visit_index = curr_path[-1].instr_index
        instruction_to_visit = ssa[visit_index]

        if instruction_to_visit is None:
            continue

        if not instruction_to_visit.vars_read:
            results.append(curr_path)
            continue

        for new_var in instruction_to_visit.vars_read:
            if not isinstance(new_var, mediumlevelil.SSAVariable):
                results.append(curr_path)
                continue

            next_var_index = ssa.get_ssa_var_definition(new_var)
            if next_var_index == None:
                """
                (Pdb) curr_path[-1]
                <il: ecx#1 = arg3#0>
                (Pdb) curr_path[-1].src.src.var
                <var void* arg3>
                """
                try:
                    param_num = list(ssa.source_function.parameter_vars).index(curr_path[-1].src.src.var)
                except ValueError:
                    results.append(curr_path[:])
                    continue
                    
                bv = ssa.source_function.view
                xrefs = bv.get_code_refs(ssa.source_function.start)
                for xref in xrefs:
                    xref_il = xref.function.get_low_level_il_at(xref.address).medium_level_il.ssa_form
                    xref_var = xref_il.params[param_num]
                    back_results = backward(xref_var)
                    for path in back_results:
                        final_path = curr_path[:]
                        final_path.extend(path)
                        results.append(final_path)
            else:
                new_path = curr_path[:]
                new_path.append(ssa[next_var_index]) 
                instruction_queue.put(new_path)

    return results
