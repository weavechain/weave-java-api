package com.weavechain.core.data;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

import ethereum.ckzg4844.CKZG4844JNI;

@AllArgsConstructor
@EqualsAndHashCode
public class KZGCommitment {

    @Getter
    private final byte[] data;

    public static KZGCommitment blobToKzgCommitment(byte[] data) {
        byte[] commitment = CKZG4844JNI.blobToKzgCommitment(data);
        return new KZGCommitment(commitment);
    }

    public static KZGCommitment computeAggregateKzgProof(List<byte[]> data) throws IOException {
        byte[] input = getDataBytes(data);
        final byte[] proof = CKZG4844JNI.computeAggregateKzgProof(input, data.size());
        return new KZGCommitment(proof);
    }

    public static boolean verifyAggregateKzgProof(List<byte[]> data, List<KZGCommitment> commitments, KZGCommitment proof) throws IOException {
        byte[] input = getDataBytes(data);
        byte[] comm = getCommitmentsBytes(commitments);
        return CKZG4844JNI.verifyAggregateKzgProof(input, comm, data.size(), proof.getData());
    }

    public static boolean verifyKzgProof(KZGCommitment commitment, KZGCommitment proof, byte[] z, byte[] y) {
        return CKZG4844JNI.verifyKzgProof(commitment.getData(), z, y, proof.getData());
    }

    private static byte[] getDataBytes(List<byte[]> data) throws IOException {
        final ByteArrayOutputStream buff = new ByteArrayOutputStream();
        for (byte[] item : data) {
            buff.write(item);
        }
        return buff.toByteArray();
    }

    private static byte[] getCommitmentsBytes(List<KZGCommitment> data) throws IOException {
        final ByteArrayOutputStream buff = new ByteArrayOutputStream();
        for (KZGCommitment item : data) {
            buff.write(item.getData());
        }
        return buff.toByteArray();
    }
}
