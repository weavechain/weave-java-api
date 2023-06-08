package com.weavechain.api.sig;

import cafe.cryptography.curve25519.*;
import io.ipfs.multibase.Base58;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class SchnorrNIZK {


    public static Transcript prove(byte[] pk, Scalar x, EdwardsPoint pt) throws NoSuchAlgorithmException {
        Scalar r = Scalar.fromBits(pk);
        EdwardsPoint u = Constants.ED25519_BASEPOINT.multiply(r);

        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Constants.ED25519_BASEPOINT.compress().toByteArray());
        md.update(pt.compress().toByteArray());
        md.update(u.compress().toByteArray());
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);
        Scalar z = k.multiplyAndAdd(x, r);

        return new Transcript(u, k, z);
    }

    public static boolean verify(EdwardsPoint pt, Transcript transcript) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Constants.ED25519_BASEPOINT.compress().toByteArray());
        md.update(pt.compress().toByteArray());
        md.update(transcript.getU().compress().toByteArray());
        byte[] digest = md.digest();
        Scalar k = Scalar.fromBytesModOrderWide(digest);

        return Arrays.equals(k.toByteArray(), transcript.getC().toByteArray())
                && Arrays.equals(
                    Constants.ED25519_BASEPOINT.multiply(transcript.getZ()).compress().toByteArray(),
                    pt.multiply(k).add(transcript.getU()).compress().toByteArray()
                );
    }

    public static Transcript prove(Scalar k) throws NoSuchAlgorithmException {
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(k);
        byte[] r = new byte[32];
        SigUtils.random().nextBytes(r);
        return SchnorrNIZK.prove(r, k, pt);
    }

    public static boolean verify(Scalar k, Transcript transcript) throws NoSuchAlgorithmException {
        EdwardsPoint pt = Constants.ED25519_BASEPOINT.multiply(k);
        return verify(pt, transcript);
    }

    @Getter
    @AllArgsConstructor
    public static class Transcript {

        private final EdwardsPoint u;

        private final Scalar c;

        private final Scalar z;

        public byte[] toBytes() throws IOException {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            outputStream.write(u.compress().toByteArray());
            outputStream.write(c.toByteArray());
            outputStream.write(z.toByteArray());

            return outputStream.toByteArray();
        }

        public String toBase58() throws IOException {
            return Base58.encode(toBytes());
        }

        public static Transcript fromBytes(byte[] input) throws InvalidEncodingException {
            ByteArrayInputStream inputStream = new ByteArrayInputStream(input);

            byte[] bu = new byte[32];
            byte[] bc = new byte[32];
            byte[] bz = new byte[32];

            inputStream.read(bu, 0, bu.length);
            inputStream.read(bc, 0, bc.length);
            inputStream.read(bz, 0, bz.length);

            return new Transcript(
                new CompressedEdwardsY(bu).decompress(),
                Scalar.fromBits(bc),
                Scalar.fromBits(bz)
            );
        }

        public static Transcript fromBase58(String input) throws InvalidEncodingException {
            return fromBytes(Base58.decode(input));
        }
    }
}