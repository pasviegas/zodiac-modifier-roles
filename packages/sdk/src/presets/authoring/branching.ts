import { ParamType } from "ethers/lib/utils"

import { Operator, ParameterType } from "../../types"

import { mapScoping } from "./matches"
import { ConditionFunction, Scoping } from "./types"

export const or =
  <S extends T, T>(
    ...branches: [
      branch_0: Scoping<S>,
      branch_1: Scoping<S>,
      ...more_branches: Scoping<S>[]
    ]
  ): ConditionFunction<T> =>
  (abiType: ParamType) => ({
    paramType: ParameterType.None,
    operator: Operator.Or,
    children: branches.map((branch) => mapScoping(branch, abiType)),
  })
