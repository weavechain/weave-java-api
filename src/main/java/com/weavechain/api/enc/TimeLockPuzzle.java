package com.weavechain.api.enc;

import com.weavechain.api.sig.SigUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@Getter
@AllArgsConstructor
public class TimeLockPuzzle {

    static final Logger logger = LoggerFactory.getLogger(TimeLockPuzzle.class);

    static final int BITS = 128;

    private final BigInteger n;

    private final BigInteger a;

    private final BigInteger t;

    private final BigInteger z;

    private final int l;

    static BigInteger bytesToBigInteger(byte[] message) {
        BigInteger result = BigInteger.ZERO;
        for (byte c : message) {
            result = result.shiftLeft(8).add(BigInteger.valueOf(c));
        }
        return result;
    }

    static protected BigInteger convertMessageToBigInteger(String message, String seedP, BigInteger n) {
        String msg = seedP + "\n" + message;
        BigInteger secret = bytesToBigInteger(msg.getBytes(StandardCharsets.UTF_8));
        if (secret.compareTo(n) > 0) {
            logger.error("Message too long");
            return null;
        } else {
            return secret;
        }
    }

    public static long benchmark(BigInteger a, BigInteger n) {
        //warmup
        TimeLockHelper.squarings(a, n, BigInteger.valueOf(10000));

        BigInteger count = BigInteger.valueOf(50000);
        long start = System.currentTimeMillis();
        TimeLockHelper.squarings(a, n, count);
        double elapsed = System.currentTimeMillis() - start;

        return (long)(count.longValue() * 1000.0 / elapsed);
    }

    public static TimeLockPuzzle createPuzzle(String message, BigInteger a, BigInteger t, int primeLength) {
        BigInteger seedP = new BigInteger(BITS, SigUtils.random());
        BigInteger seedQ = new BigInteger(BITS, SigUtils.random());

        BigInteger pow = BigInteger.ONE.shiftLeft(primeLength);
        BigInteger p = TimeLockHelper.getNextPrime(TimeLockHelper.p5.modPow(seedP, pow));
        BigInteger q = TimeLockHelper.getNextPrime(TimeLockHelper.p5.modPow(seedQ, pow));

        BigInteger n = p.multiply(q);

        BigInteger pm1 = p.subtract(BigInteger.ONE);
        BigInteger qm1 = q.subtract(BigInteger.ONE);

        BigInteger phi = pm1.multiply(qm1);

        BigInteger e;
        do  {
            e = new BigInteger(2 * primeLength, SigUtils.random());
        } while (e.compareTo(phi) >= 0 || e.gcd(phi).compareTo(BigInteger.valueOf(1)) != 0);

        BigInteger u = BigInteger.TWO.modPow(t, phi);
        BigInteger w = a.modPow(u, n);

        BigInteger m = convertMessageToBigInteger(message, seedP.toString(), n);
        BigInteger z = m != null ? m.xor(w) : null;

        return new TimeLockPuzzle(n, a, t, z, primeLength);
    }

    public static TimeLockPuzzle encrypt(String message, long seconds, int primeLength) {
        BigInteger a = new BigInteger(16, SigUtils.random());

        //This is machine dependant! Time intervals need to be large enough and have some tolerance or the hardware solving the puzzle known. Also, FPGA is a deal-breaker
        TimeLockPuzzle temp = TimeLockPuzzle.createPuzzle("benchmark", a, BigInteger.ONE, primeLength);
        long benchmark = TimeLockPuzzle.benchmark(a, temp.getN());
        BigInteger requiredSquarings = BigInteger.valueOf(benchmark).multiply(BigInteger.valueOf(seconds));

        return TimeLockPuzzle.createPuzzle(message, a, requiredSquarings, primeLength);
    }

    public String toJson() {
        Map<String, Object> result = Map.of(
                "n", n,
                "a", a,
                "t", t,
                "z", z,
                "l", l
        );
        return Utils.getGson().toJson(result);
    }

    public static TimeLockPuzzle fromJson(String data) {
        return Utils.getGson().fromJson(data, TimeLockPuzzle.class);
    }
}