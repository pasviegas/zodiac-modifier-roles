import { expect } from "chai";
import { BigNumberish } from "ethers";
import { defaultAbiCoder } from "ethers/lib/utils";
import hre, { deployments, waffle } from "hardhat";

import "@nomiclabs/hardhat-ethers";

import { Operator, ExecutionOptions, ParameterType } from "./utils";

describe("Operator", async () => {
  const timestampNow = () => Math.floor(new Date().getTime() / 1000);

  const setup = deployments.createFixture(async () => {
    await deployments.fixture();
    const timestamp = timestampNow();

    const Avatar = await hre.ethers.getContractFactory("TestAvatar");
    const avatar = await Avatar.deploy();

    const TestContract = await hre.ethers.getContractFactory("TestContract");
    const testContract = await TestContract.deploy();

    const [owner, invoker] = waffle.provider.getWallets();

    const Modifier = await hre.ethers.getContractFactory("Roles");
    const modifier = await Modifier.deploy(
      owner.address,
      avatar.address,
      avatar.address
    );

    await modifier.enableModule(invoker.address);

    async function setAllowance(
      allowanceKey: string,
      {
        balance,
        maxBalance,
        refillAmount,
        refillInterval,
        refillTimestamp,
      }: {
        balance: BigNumberish;
        maxBalance?: BigNumberish;
        refillAmount: BigNumberish;
        refillInterval: BigNumberish;
        refillTimestamp: BigNumberish;
      }
    ) {
      await modifier
        .connect(owner)
        .setAllowance(
          allowanceKey,
          balance,
          maxBalance || 0,
          refillAmount,
          refillInterval,
          refillTimestamp
        );
    }

    async function setRole(allowanceKey: string) {
      const ROLE_ID = 0;
      const SELECTOR = testContract.interface.getSighash(
        testContract.interface.getFunction("fnWithSingleParam")
      );

      await modifier
        .connect(owner)
        .assignRoles(invoker.address, [ROLE_ID], [true]);

      // set it to true
      await modifier.connect(owner).scopeTarget(ROLE_ID, testContract.address);
      await modifier.connect(owner).scopeFunction(
        ROLE_ID,
        testContract.address,
        SELECTOR,
        [
          {
            parent: 0,
            paramType: ParameterType.AbiEncoded,
            operator: Operator.Matches,
            compValue: "0x",
          },
          {
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.WithinAllowance,
            compValue: defaultAbiCoder.encode(["string"], [allowanceKey]),
          },
        ],
        ExecutionOptions.None
      );

      async function invoke(a: number) {
        return modifier
          .connect(invoker)
          .execTransactionFromModule(
            testContract.address,
            0,
            (await testContract.populateTransaction.fnWithSingleParam(a))
              .data as string,
            0
          );
      }

      return { invoke, modifier };
    }

    async function setRoleTwoParams(allowanceKey: string) {
      const ROLE_ID = 0;
      const SELECTOR = testContract.interface.getSighash(
        testContract.interface.getFunction("fnWithTwoParams")
      );

      await modifier
        .connect(owner)
        .assignRoles(invoker.address, [ROLE_ID], [true]);

      // set it to true
      await modifier.connect(owner).scopeTarget(ROLE_ID, testContract.address);
      await modifier.connect(owner).scopeFunction(
        ROLE_ID,
        testContract.address,
        SELECTOR,
        [
          {
            parent: 0,
            paramType: ParameterType.AbiEncoded,
            operator: Operator.Matches,
            compValue: "0x",
          },
          {
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.WithinAllowance,
            compValue: defaultAbiCoder.encode(["string"], [allowanceKey]),
          },
          {
            parent: 0,
            paramType: ParameterType.Static,
            operator: Operator.WithinAllowance,
            compValue: defaultAbiCoder.encode(["string"], [allowanceKey]),
          },
        ],
        ExecutionOptions.None
      );

      async function invoke(a: number, b: number) {
        return modifier
          .connect(invoker)
          .execTransactionFromModule(
            testContract.address,
            0,
            (await testContract.populateTransaction.fnWithTwoParams(a, b))
              .data as string,
            0
          );
      }

      return { invoke, modifier };
    }

    return {
      timestamp,
      setAllowance,
      setRole,
      setRoleTwoParams,
    };
  });

  describe("WithinAllowance - Check", () => {
    it("passes a check with enough balance available and no refill (interval = 0)", async () => {
      const { setAllowance, setRole } = await setup();

      const allowanceKey = "Something   ";
      await setAllowance(allowanceKey, {
        balance: 1000,
        refillInterval: 0,
        refillAmount: 0,
        refillTimestamp: 0,
      });

      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(1001)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );

      await expect(invoke(1000)).to.not.be.reverted;
      await expect(invoke(1)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
    });

    it("passes a check with only from balance and refill available", async () => {
      const { setAllowance, setRole, timestamp } = await setup();
      // more than one byte per char
      const allowanceKey = "á 中文的东西 a";
      await setAllowance(allowanceKey, {
        balance: 333,
        refillInterval: 1000,
        refillAmount: 100,
        refillTimestamp: timestamp - 60,
      });
      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(334)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      await expect(invoke(333)).to.not.be.reverted;
      await expect(invoke(1)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
    });

    it("passes a check balance from available+refill", async () => {
      const { setAllowance, setRole, timestamp } = await setup();
      const allowanceKey = "BBAL2-34/44";
      await setAllowance(allowanceKey, {
        balance: 250,
        refillInterval: 500,
        refillAmount: 100,
        refillTimestamp: timestamp - 750,
      });

      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(351)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      await expect(invoke(350)).to.not.be.reverted;
      await expect(invoke(1)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
    });

    it("fails a check, with some balance and not enough elapsed for next refill", async () => {
      const { setAllowance, setRole, timestamp } = await setup();
      const allowanceKey = "3344";
      await setAllowance(allowanceKey, {
        balance: 250,
        refillInterval: 1000,
        refillAmount: 100,
        refillTimestamp: timestamp - 50,
      });
      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(251)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      await expect(invoke(250)).to.not.be.reverted;
      await expect(invoke(1)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
    });

    it("passes a check with balance from refill and bellow maxBalance", async () => {
      const { setAllowance, setRole, timestamp } = await setup();
      const interval = 10000;
      const allowanceKey = "5KmDp7p+5ZuG5oiR5rWL5rWL6YeM5rWL";
      await setAllowance(allowanceKey, {
        balance: 0,
        maxBalance: 1000,
        refillInterval: interval,
        refillAmount: 9999999,
        refillTimestamp: timestamp - interval * 10,
      });
      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(1001)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      await expect(invoke(1000)).to.not.be.reverted;
    });

    it("fails a check with balance from refill but capped by maxBalance", async () => {
      const { setAllowance, setRole, timestamp } = await setup();
      const allowanceKey = "elevator pause inflict whisper";
      await setAllowance(allowanceKey, {
        balance: 0,
        maxBalance: 9000,
        refillInterval: 1000,
        refillAmount: 10000,
        refillTimestamp: timestamp - 5000,
      });
      const { invoke } = await setRole(allowanceKey);

      await expect(invoke(9001)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      await expect(invoke(9000)).to.not.be.reverted;
    });
  });

  describe("WithinAllowance - Track", async () => {
    it("Updates tracking, even with multiple parameters referencing the same limit", async () => {
      const { setAllowance, setRoleTwoParams } = await setup();
      const allowanceKey = "c@pT!vate#b0lt^s1ren";
      await setAllowance(allowanceKey, {
        balance: 3000,
        refillInterval: 0,
        refillAmount: 0,
        refillTimestamp: 0,
      });
      const { invoke, modifier } = await setRoleTwoParams(allowanceKey);

      let allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(3000);

      await expect(invoke(3001, 3001)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(3000);

      await expect(invoke(1500, 1500)).to.not.be.reverted;
      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(0);
    });

    it("Fails at tracking, when multiple parameters referencing the same limit overspend", async () => {
      const { setAllowance, setRoleTwoParams } = await setup();
      const allowanceKey = "鸡pąpā世界nø";
      await setAllowance(allowanceKey, {
        balance: 3000,
        refillInterval: 0,
        refillAmount: 0,
        refillTimestamp: 0,
      });
      const { invoke, modifier } = await setRoleTwoParams(allowanceKey);

      let allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(3000);

      await expect(invoke(3000, 1)).to.be.revertedWith(
        `AllowanceExceeded("${allowanceKey}")`
      );
      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(3000);
    });

    it("Updates refillTimestamp starting from zero", async () => {
      const { setAllowance, setRole } = await setup();

      const interval = 600;

      const allowanceKey = "ƁΔʆøḽǫШȦֆ";
      await setAllowance(allowanceKey, {
        balance: 1,
        refillInterval: interval,
        refillAmount: 0,
        refillTimestamp: 0,
      });
      const { invoke, modifier } = await setRole(allowanceKey);

      let allowance = await modifier.allowances(allowanceKey);
      expect(allowance.balance).to.equal(1);
      expect(allowance.refillTimestamp).to.equal(0);

      await expect(invoke(0)).to.not.be.reverted;
      const now = timestampNow();

      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp.toNumber()).to.be.greaterThan(0);
      expect(now - allowance.refillTimestamp.toNumber()).to.be.lessThanOrEqual(
        interval * 2
      );
    });

    it("Does not updates refillTimestamp if interval is zero", async () => {
      const { setAllowance, setRole } = await setup();

      const allowanceKey = "‡àêåûÿ¡»¿";
      await setAllowance(allowanceKey, {
        balance: 1,
        refillInterval: 0,
        refillAmount: 0,
        refillTimestamp: 0,
      });
      const { invoke, modifier } = await setRole(allowanceKey);

      await expect(invoke(0)).to.not.be.reverted;

      const allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp).to.equal(0);
    });

    it("Updates refillTimestamp from past timestamp", async () => {
      const { setAllowance, setRole } = await setup();

      const interval = 600;
      const initialTimestamp = timestampNow() - 2400;

      const allowanceKey = "Some/other/key";
      await setAllowance(allowanceKey, {
        balance: 1,
        refillInterval: interval,
        refillAmount: 0,
        refillTimestamp: initialTimestamp,
      });
      const { invoke, modifier } = await setRole(allowanceKey);

      let allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp).to.equal(initialTimestamp);

      await expect(invoke(0)).to.not.be.reverted;

      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp.toNumber()).to.be.greaterThan(
        initialTimestamp
      );
    });

    it("Does not update refillTimestamp from future timestamp", async () => {
      const { setAllowance, setRole } = await setup();

      const interval = 600;
      const initialTimestamp = timestampNow() + 1200;

      const allowanceKey = "Hello World!";
      await setAllowance(allowanceKey, {
        balance: 1,
        refillInterval: interval,
        refillAmount: 0,
        refillTimestamp: initialTimestamp,
      });
      const { invoke, modifier } = await setRole(allowanceKey);

      let allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp).to.equal(initialTimestamp);

      await expect(invoke(0)).to.not.be.reverted;

      allowance = await modifier.allowances(allowanceKey);
      expect(allowance.refillTimestamp).to.equal(initialTimestamp);
    });
  });
});
