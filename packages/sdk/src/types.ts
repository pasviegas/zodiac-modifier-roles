import { BigNumber } from "ethers"

import SUBGRAPH from "./subgraph"

export type NetworkId = keyof typeof SUBGRAPH

export enum ExecutionOptions {
  None = 0,
  Send = 1,
  DelegateCall = 2,
  Both = 3,
}

export enum Clearance {
  None = 0,
  Target = 1,
  Function = 2,
}

export enum ParameterType {
  None = 0,
  Static = 1,
  Dynamic = 2,
  Tuple = 3,
  Array = 4,
  AbiEncoded = 5,
}

export enum Operator {
  // 00:    EMPTY EXPRESSION (default, always passes)
  //          paramType: Static / Dynamic
  //          🚫 children
  //          🚫 compValue
  Pass = 0,
  // ------------------------------------------------------------
  // 01-04: BOOLEAN EXPRESSIONS
  //          paramType: None
  //          ✅ children
  //          🚫 compValue
  And = 1,
  Or = 2,
  Xor = 3,
  Not = 4,
  // ------------------------------------------------------------
  // 05-16: COMPLEX EXPRESSIONS
  //          paramType: AbiEncoded / Tuple / Array,
  //          ✅ children
  //          🚫 compValue
  Matches = 5,
  ArraySome = 6,
  ArrayEvery = 7,
  ArraySubset = 8,

  // ------------------------------------------------------------
  // 17-31: COMPARISON EXPRESSIONS
  //          paramType: Static / Dynamic / Tuple / Array / AbiEncoded
  //          🚫 children
  //          ✅ compValue
  EqualTo = 17,
  GreaterThan = 18,
  LessThan = 19,
  Bitmask = 20,
  WithinAllowance = 29,
  EtherWithinAllowance = 30,
  CallWithinAllowance = 31,
}

export interface Role {
  key: string
  members: string[]
  targets: Target[]
  allowances: Allowance[]
}

export interface Target {
  address: string
  clearance: Clearance
  executionOptions: ExecutionOptions
  functions: Function[]
}

export interface Function {
  selector: string
  executionOptions: ExecutionOptions
  wildcarded: boolean
  condition?: Condition
}

export interface Condition {
  paramType: ParameterType
  operator: Operator
  compValue?: string
  children?: Condition[]
}

export interface ConditionFlat {
  parent: number
  paramType: ParameterType
  operator: Operator
  compValue?: string
}

export interface Allowance {
  key: string
  refillInterval: number
  refillAmount: BigNumber
  refillTimestamp: number
  maxBalance: BigNumber
  balance: BigNumber
}
