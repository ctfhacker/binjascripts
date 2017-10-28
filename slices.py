import binaryninja
from binaryninja import *
from binaryninja.mediumlevelil import SSAVariable, MediumLevelILFunction

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
    # switch to SSA form (this does nothing if it's already SSA).

    function = instruction.function
    if not isinstance(function, MediumLevelILFunction):
        ssa = function.medium_level_il.ssa_form
    else:
        ssa = function.ssa_form

    if not isinstance(instruction.ssa_form.operands[0], SSAVariable):
        return set()

    function = instruction.function
    instruction_queue = set([instruction.ssa_form.instr_index])
    visited_instructions = set()

    variables = set()

    while instruction_queue:
        visit_index = instruction_queue.pop()

        if visit_index is None or visit_index in visited_instructions:
            continue

        instruction_to_visit = function[visit_index]

        if instruction_to_visit is None:
            continue

        for new_var in instruction_to_visit.vars_read:
            instruction_queue.add(
                function.get_ssa_var_definition(
                    new_var
                )
            )

        variables.update(
            [(var.var.identifier, var.version)
                for var in instruction_to_visit.vars_read]
        )

        visited_instructions.add(visit_index)

    return visited_instructions

