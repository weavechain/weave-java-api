package com.weavechain.api.pre;

import com.weavechain.api.auth.BLSKeyPair;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.encrypt.KeysProvider;
import com.weavechain.core.encrypt.EncryptionConfig;
import com.weavechain.api.enc.EncryptionHelper;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.ssohub.crypto.ecc.Pre;
import org.ssohub.crypto.ecc.libecc;

import java.security.PrivateKey;
import java.util.List;
import java.util.Random;

import static org.ssohub.crypto.ecc.Pre.*;

public class PREHelper {

    static final Logger logger = LoggerFactory.getLogger(PREHelper.class);

    private static final boolean BLS_RAND_SEED = true;

    public static BLSKeyPair generateKeyPair() {
        byte[] pk = new byte[libecc.ecc_pre_schema1_PUBLICKEYSIZE];
        byte[] sk = new byte[libecc.ecc_pre_schema1_PRIVATEKEYSIZE];
        libecc.ecc_pre_schema1_KeyGen(pk, sk);
        return new BLSKeyPair(pk, sk);
    }

    public static BLSKeyPair deriveKeyPair(PrivateKey key) {
        try {
            byte[] pk = new byte[libecc.ecc_pre_schema1_PUBLICKEYSIZE];
            byte[] sk = new byte[libecc.ecc_pre_schema1_PRIVATEKEYSIZE];

            byte[] seed;
            if (BLS_RAND_SEED) {
                Random r = new Random();
                r.nextInt();
                seed = KeysProvider.getMaskedSecret((BCECPrivateKey) key, r);
            } else {
                seed = KeysProvider.getBytes(((BCECPrivateKey) key).getD());
            }

            libecc.ecc_pre_schema1_DeriveKey(pk, sk, seed);
            return new BLSKeyPair(pk, sk);
        } catch (Throwable e) {
            logger.warn("Failed generating BLS key, libecc not loaded");
            return null;
        }
    }

    public static EncryptionConfig encryptRecords(DataLayout layout, List<List<Object>> records) {
        return encryptRecords(layout, records, EncryptionConfig.AES);
    }

    public static EncryptionConfig encryptRecords(DataLayout layout, List<List<Object>> records, String encryptionAlgo) {
        byte[] message = Pre.pre_schema1_MessageGen();

        EncryptionConfig encryptionConfig = new EncryptionConfig(encryptionAlgo, Base64.encodeBase64String(message), null);
        EncryptionHelper.encryptRecords(layout, encryptionConfig, records);

        return encryptionConfig;
    }

    public static ProxyEncryptedData prepareForProxy(String encodedSecretKey, byte[] readerPubKey) {
        Pre.KeyPair ephKeyPair = Pre.pre_schema1_KeyGen();
        Pre.SigningKeyPair signingKeyPair = Pre.pre_schema1_SigningKeyGen();

        return new ProxyEncryptedData(
                Pre.pre_schema1_Encrypt(Base64.decodeBase64(encodedSecretKey), ephKeyPair.pk, signingKeyPair),
                Pre.pre_schema1_ReKeyGen(ephKeyPair.sk, readerPubKey, signingKeyPair),
                signingKeyPair.spk,
                readerPubKey
        );
    }

    public static byte[] reEncode(ProxyEncryptedData data, SigningKeyPair signingProxy, byte[] readerPubKey) {
        return Pre.pre_schema1_ReEncrypt(
                data.getEncoded(),
                data.getReencryptionKey(),
                data.getWriterSignPubKey(),
                readerPubKey,
                signingProxy
        );
    }

    public static byte[] decode(byte[] encoded, byte[] readerPrivateKey, byte[] proxyPubKey) {
        return Pre.pre_schema1_DecryptLevel2(
                encoded,
                readerPrivateKey,
                proxyPubKey
        );
    }
}