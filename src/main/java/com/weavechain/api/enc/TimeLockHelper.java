package com.weavechain.api.enc;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class TimeLockHelper {

    public final static int PRIME_CERTAINTY_THRESHOLD = 50;

    protected static final BigInteger p5 = BigInteger.valueOf(5);

    public static BigInteger getNextPrime(BigInteger value) {
        BigInteger p = value;

        if (!p.testBit(0)) {
            p = p.add(BigInteger.ONE);
        }

        while (!p.isProbablePrime(PRIME_CERTAINTY_THRESHOLD)) {
            p = p.add(BigInteger.TWO);
        }

        return(p);
    }

    public static BigInteger squarings(BigInteger a, BigInteger mod, BigInteger count) {
        BigInteger result = a;
        BigInteger idx = count;
        while (!idx.equals(BigInteger.ZERO)) {
            result = result.modPow(BigInteger.TWO, mod);
            idx = idx.subtract(BigInteger.ONE);
        }
        return result;
    }

    public static String solvePuzzle(TimeLockPuzzle puzzle) {
        BigInteger w = TimeLockHelper.squarings(puzzle.getA(), puzzle.getN(), puzzle.getT());
        BigInteger msg = w.xor(puzzle.getZ());
        String fullMessage = new String(msg.toByteArray(), StandardCharsets.UTF_8);

        int idx = fullMessage.indexOf("\n");
        BigInteger seedP = new BigInteger(fullMessage.substring(0, idx));

        BigInteger twoPower = BigInteger.ONE.shiftLeft(puzzle.getL());
        BigInteger testP, testQ;
        testP = TimeLockHelper.getNextPrime(p5.modPow(seedP, twoPower));
        testQ = puzzle.getN().divide(testP);
        boolean match = puzzle.getN().mod(testP).equals(BigInteger.ZERO) && testQ.isProbablePrime(TimeLockHelper.PRIME_CERTAINTY_THRESHOLD);
        return match ? fullMessage.substring(idx + 1) : null;
    }
}