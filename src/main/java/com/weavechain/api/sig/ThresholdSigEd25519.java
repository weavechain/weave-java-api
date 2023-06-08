package com.weavechain.api.sig;

//using version with invert() from https://github.com/parinayc20/curve25519-elisabeth.git
import cafe.cryptography.curve25519.*;

import io.ipfs.multibase.Base58;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;

@AllArgsConstructor
public class ThresholdSigEd25519 {

    @Getter
    private final int t;

    private final int n;

    private static final byte[] PREFIX = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

    private static final Object syncObj = new Object();

    private static List<Scalar> cachedCoef;

    private static int cachedSize;

    public ThresholdSigEd25519Params generate() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, IOException, NoSuchProviderException {

        byte[] secret = new byte[32];
        SigUtils.random().nextBytes(secret);

        //private key build, this is not ok to be done centralized
        byte[] publicKey = createPublicKey(secret);
        Scalar privateKey = createPrivateKey(secret);

        //private key shares generation
        List<Scalar> privateShares = shamirSplit(privateKey, n);

        return new ThresholdSigEd25519Params(
                privateKey,
                publicKey,
                privateShares,
                null
        );
    }

    private List<Scalar> shamirSplit(Scalar secret, int n) {
        List<Scalar> result = new ArrayList<>();

        Polynom poly = new Polynom(t - 1, secret);
        for (int i = 0; i < n; i++) {
            Scalar x = SigUtils.scalarFromBigInteger(BigInteger.valueOf(i + 1));
            result.add(poly.at(x));
        }

        return result;
    }

    public List<EdwardsPoint> gatherRi(ThresholdSigEd25519Params params, String toSign) throws NoSuchAlgorithmException {
        //done by each node separately
        List<Scalar> Rs = new ArrayList<>();
        List<EdwardsPoint> Ri = new ArrayList<>();
        for (int i = 0; i < t; i++) {
            Scalar privateShare = params.getPrivateShares().get(i);
            Scalar rs = computeRs(privateShare, toSign);

            Rs.add(rs);
            EdwardsPoint res = mulBasepoint(rs);
            Ri.add(res);
        }

        params.setSig(Rs);

        return Ri;
    }

    public Scalar computeRi(Scalar privateShare, String toSign) throws NoSuchAlgorithmException {
        return computeRs(privateShare, toSign);
    }

    public EdwardsPoint computeR(List<EdwardsPoint> Ri) {
        //done by coordinator
        EdwardsPoint R = Ri.get(0);
        for (int i = 1; i < t; i++) {
            R = R.add(Ri.get(i));
        }
        return R;
    }

    public Scalar computeK(byte[] publicKey, EdwardsPoint R, String toSign) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(R.compress().toByteArray());
        md.update(publicKey);
        md.update(toSign.getBytes(StandardCharsets.UTF_8));
        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }

    public List<Scalar> gatherSignatures(ThresholdSigEd25519Params params, Scalar k) {
        //done by each node
        List<Scalar> res = new ArrayList<>();
        for (int i = 0; i < t; i++) {
            Scalar privateShare = params.getPrivateShares().get(i);

            Scalar sig = params.getSig().get(i);
            Scalar pt = computeSig(k, i + 1, privateShare, sig);
            res.add(pt);
        }

        return res;
    }

    public Scalar computeSignature(int index, Scalar privateShare, Scalar sig, Scalar k) {
        return computeSig(k, index, privateShare, sig);
    }

    public byte[] computeSignature(EdwardsPoint R, List<Scalar> res) throws IOException {
        //done by coordinator
        Scalar s = Scalar.ZERO;
        for (int i = 0; i < t; i++) {
            s = s.add(res.get(i));
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(R.compress().toByteArray());
        outputStream.write(s.toByteArray());
        return outputStream.toByteArray();
    }

    private Scalar computeSig(Scalar k, int index, Scalar privateShare, Scalar sig) {
        List<Scalar> coef = getLagrangeCoef(t);
        return privateShare.multiply(coef.get(index - 1)).multiply(k).add(sig);
    }

    private Scalar computeRs(Scalar privateShare, String toSign) throws NoSuchAlgorithmException {
        byte[] rnd = new byte[64];
        SigUtils.random().nextBytes(rnd);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(PREFIX);
        md.update(privateShare.toByteArray());
        md.update(toSign.getBytes(StandardCharsets.UTF_8));
        md.update(rnd);

        byte[] digest = md.digest();
        return Scalar.fromBytesModOrderWide(digest);
    }

    public static EdwardsPoint mulBasepoint(Scalar input) {
        return Constants.ED25519_BASEPOINT.multiply(input);
    }

    private byte[] createPublicKey(byte[] secret) throws NoSuchAlgorithmException {
        byte[] hash = sha512(secret);
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        Scalar s = Scalar.fromBits(Arrays.copyOfRange(hash, 0, 32));
        return mulBasepoint(s).compress().toByteArray();
    }

    private Scalar createPrivateKey(byte[] secret) throws NoSuchAlgorithmException {
        byte[] hash = sha512(secret);
        hash[0] &= 248;
        hash[31] &= 127;
        hash[31] |= 64;

        return Scalar.fromBits(Arrays.copyOfRange(hash, 0, 32));
    }

    private byte[] sha512(byte[] pk) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(pk);
        return md.digest();
    }

    public static List<Scalar> getLagrangeCoef(int size) {
        if (cachedCoef != null && cachedSize >= size) {
            return cachedCoef;
        }

        List<Scalar> index = new ArrayList<>();
        List<Scalar> lagrangeCoef = new ArrayList<>();
        for (int i = 1; i <= size; i++) {
            index.add(SigUtils.scalarFromBigInteger(BigInteger.valueOf(i)));
            lagrangeCoef.add(Scalar.ONE);
        }

        for (int i = 1; i <= size; i++) {
            for (int j = 1; j <= size; j++) {
                if (i != j) {
                    Scalar dx = (index.get(j - 1).subtract(index.get(i - 1))).invert();
                    Scalar factor = index.get(j - 1).multiply(dx);
                    lagrangeCoef.set(i - 1, lagrangeCoef.get(i - 1).multiply(factor));
                }
            }
        }

        synchronized (syncObj) {
            if (cachedSize < size) {
                cachedCoef = lagrangeCoef;
                cachedSize = size;
            }
        }
        return lagrangeCoef;
    }

    public static boolean verify(byte[] publicKey, String signature, byte[] signed) throws NoSuchAlgorithmException, InvalidEncodingException {
        byte[] sig = Base58.decode(signature);
        byte[] R = Arrays.copyOfRange(sig, 0, 32);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(R);
        md.update(publicKey);
        md.update(signed);
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);

        EdwardsPoint negP = new CompressedEdwardsY(publicKey).decompress().negate();

        Scalar s = Scalar.fromBits(Arrays.copyOfRange(sig, 32, sig.length));
        EdwardsPoint pt = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(k, negP, s);

        byte[] repr = pt.compress().toByteArray();
        return Arrays.equals(repr, R);
    }

    public static class Polynom {

        private final List<Scalar> coefficients = new ArrayList<>();

        public Polynom(int order, Scalar a0) {
            coefficients.add(a0);
            for (int i = 1; i < order; i++) {
                byte[] input = new byte[32];
                SigUtils.random().nextBytes(input);
                coefficients.add(Scalar.fromBits(input));
            }
        }

        public Scalar at(Scalar x) {
            Scalar res = coefficients.get(0);

            Scalar cp = Scalar.ONE;
            for (int i = 1; i < coefficients.size(); i++) {
                cp = cp.multiply(x);
                res = coefficients.get(i).multiplyAndAdd(cp, res);
            }

            return res;
        }
    }
}