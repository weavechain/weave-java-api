package com.weavechain.core.encrypt;

import com.swiftcryptollc.crypto.provider.KyberJCE;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSASecurityProvider;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import net.thiim.dilithium.interfaces.DilithiumParameterSpec;
import net.thiim.dilithium.interfaces.DilithiumPrivateKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKey;
import net.thiim.dilithium.interfaces.DilithiumPublicKeySpec;
import net.thiim.dilithium.provider.DilithiumProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import org.bitcoinj.base.Base58;

public class KeysProvider {

    //TODO: split, cleanup

    static final Logger logger = LoggerFactory.getLogger(KeysProvider.class);

    public static final int MAX_B58_LEN = 55;

    public static final String PREFIX = "weave";

    private static final SecureRandom RND = new SecureRandom();

    public static final boolean ED_RAND_SEED = true;

    public static final String ED_CURVE = "Ed25519";

    public static final String POST_QUANTUM_PROVIDER = "BCPQC";

    public static DilithiumParameterSpec DILITHIUM_PARAM_SPEC = DilithiumParameterSpec.LEVEL3;

    private static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

    private static final Object syncObj = new Object();
    private static volatile KeyExchange instance = null;

    public static boolean useDilithium = false;

    public static final BigInteger RSA_PUBLIC_EXPONENT = new BigInteger("65537");

    public static final int RSA_STRENGTH = 2048;

    public static final int RSA_CERTAINTY = 112;

    public static final int PSS_SALT_LEN = 20;

    public static KeyExchange getInstance() {
        if (instance == null) {
            synchronized (syncObj) {
                if (instance == null) {
                    Security.setProperty("crypto.policy", "unlimited");
                    Security.addProvider(new BouncyCastleProvider());
                    Security.addProvider(new EdDSASecurityProvider());
                    Security.addProvider(new BouncyCastlePQCProvider());
                    Security.addProvider(new DilithiumProvider());
                    instance = new ECIESKeys();

                    try {
                        Security.addProvider(new KyberJCE());
                    } catch (Throwable e) {
                        logger.warn("Failed initializing KyberJCE, quantum resistant auth not usable\nUse --add-opens=java.base/sun.security.x509=ALL-UNNAMED --add-exports=java.base/sun.security.util=ALL-UNNAMED");
                    }
                }
            }
        }
        return instance;
    }

    public static void initSigning(String algorithm) {
        useDilithium = algorithm != null && algorithm.toLowerCase().contains("dilithium");
        if (useDilithium && algorithm != null) {
            if ("dilithium3".equals(algorithm.toLowerCase())) {
                DILITHIUM_PARAM_SPEC = DilithiumParameterSpec.LEVEL3;
            } else if ("dilithium5".equals(algorithm.toLowerCase())) {
                DILITHIUM_PARAM_SPEC = DilithiumParameterSpec.LEVEL5;
            }
        }
    }

    private static String readKeyFromFile(String file) {
        String hexEncodedKey = null;
        try {
            String fileContent = Files.readString(Paths.get(file)).trim();
            if (fileContent.startsWith("ssh-rsa ")) {
                fileContent = fileContent.substring(8).trim();
            }
            if (fileContent.contains(" ")) {
                fileContent = fileContent.substring(0, fileContent.indexOf(" "));
            }

            hexEncodedKey = fileContent;
        } catch (IOException e) {
            logger.error("Failed opening private key file", e);
        }
        return hexEncodedKey;
    }

    public static String readEncodedKey(String encodedKey, String file) {
        if (encodedKey != null && !encodedKey.trim().isEmpty()) {
            return encodedKey.trim();
        } else if (file != null) {
            return KeysProvider.readKeyFromFile(file);
        } else {
            return null;
        }
    }

    public static String getBase58Key(String key) {
        return key;
    }

    public static String getBase58Key(PublicKey key) {
        if (key instanceof BCECPublicKey) {
            return KeysProvider.PREFIX + Base58.encode(((BCECPublicKey) key).getQ().getEncoded(true));
        } else {
            return key != null ? Hex.toHexString(key.getEncoded()) : null;
        }
    }

    public static byte[] getBytes(byte[] input, int minlen) {
        if (input.length < minlen) {
            byte[] out = new byte[32];
            System.arraycopy(input, 0, out, 32 - input.length, input.length);
            return out;
        } else {
            return input;
        }
    }

    public static String getBase58Key(PrivateKey key) {
        if (key instanceof BCECPrivateKey) {
            byte[] bytes = getBytes(((BCECPrivateKey) key).getD().toByteArray(), 32);
            if (bytes.length == 33) {
                bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
            }
            return Base58.encode(bytes);
        } else {
            return key != null ? Hex.toHexString(key.getEncoded()) : null;
        }
    }

    public static BigInteger getBigInt(PublicKey key) {
        if (key instanceof BCECPublicKey) {
            return new BigInteger(((BCECPublicKey) key).getQ().getEncoded(true));
        } else if (key != null) {
            byte[] pubEncoded = key.getEncoded();
            if (pubEncoded.length > Ed25519Prefix.length && Arrays.equals(Arrays.copyOfRange(pubEncoded, 0, Ed25519Prefix.length), Ed25519Prefix)) {
                return new BigInteger(Arrays.copyOfRange(pubEncoded, Ed25519Prefix.length, pubEncoded.length));
            } else {
                return new BigInteger(pubEncoded);
            }
        } else {
            return null;
        }
    }

    public static byte[] getBytes(PublicKey key) {
        if (key instanceof BCECPublicKey) {
            return ((BCECPublicKey) key).getQ().getEncoded(true);
        } else if (key instanceof DilithiumPublicKey) {
            return key.getEncoded();
        } else if (key != null) {
            byte[] pubEncoded = key.getEncoded();
            if (pubEncoded.length > Ed25519Prefix.length && Arrays.equals(Arrays.copyOfRange(pubEncoded, 0, Ed25519Prefix.length), Ed25519Prefix)) {
                return Arrays.copyOfRange(pubEncoded, Ed25519Prefix.length, pubEncoded.length);
            } else {
                return pubEncoded;
            }
        } else {
            return null;
        }
    }

    public static BigInteger getBigInt(PrivateKey key) {
        if (key instanceof BCECPrivateKey) {
            return new BigInteger(((BCECPrivateKey) key).getD().toByteArray());
        } else {
            return key != null ? new BigInteger(key.getEncoded()) : null;
        }
    }

    public static byte[] getBytes(BigInteger value) {
        int numBytes = 32;
        byte[] src = value.toByteArray();
        byte[] dest = new byte[numBytes];
        boolean isSign = src.length == numBytes + 1 && src[0] == 0;
        int length = isSign ? src.length - 1 : src.length;
        System.arraycopy(src, isSign ? 1 : 0, dest, numBytes - length, length);
        return dest;
    }

    public static String derivePublicSigKey(PrivateKey key) {
        KeyPair sigKeys = KeysProvider.deriveAccountSigKeyPair(key);
        return sigKeys != null && sigKeys.getPublic() != null ? Base58.encode(sigKeys.getPublic().getEncoded()) : null;
    }

    public static String derivePublicRSAKey(PrivateKey key) {
        try {
            AsymmetricCipherKeyPair sigKeys = KeysProvider.deriveAccountRSAKeyPair(key);
            return sigKeys != null && sigKeys.getPublic() != null ? Base58.encode(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(sigKeys.getPublic()).getEncoded()) : null;
        } catch (Exception e) {
            logger.warn("Failed generating RSA key");
            return null;
        }
    }

    public static RSAKeyParameters decodeRSAPublicKey(byte[] encoding) {
        try {
            SubjectPublicKeyInfo decodedSubjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(encoding);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedSubjectPublicKeyInfo.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
            BCRSAPublicKey rsaPublicKey = (BCRSAPublicKey) keyFactory.generatePublic(keySpec);
            return new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
        } catch (Exception e) {
            logger.error("Failed decoding key", e);
            return null;
        }
    }

    public static PublicKey pubEd25519FromBigInt(BigInteger key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(Ed25519Prefix);
        outputStream.write(key.toByteArray());
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(outputStream.toByteArray()));
    }

    public static KeyPair generateEd25519KeyPair() {
        try {
            KeyFactory kf = KeyFactory.getInstance("EdDSA", "EdDSA");
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED_CURVE);
            byte[] secretKey = new byte[32];
            RND.nextBytes(secretKey);

            EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(secretKey, spec);
            PrivateKey privKey = kf.generatePrivate(privKeySpec);
            EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA(), spec);
            PublicKey pubkey = kf.generatePublic(pubKeySpec);

            return new KeyPair(pubkey, privKey);
        } catch (Exception e) {
            logger.error("Failed creating key", e);
            return null;
        }
    }

    public static KeyPair deriveAccountSigKeyPair(PrivateKey key) {
        try {
            if (useDilithium) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("Dilithium");

                Random r = new Random();
                byte[] secretKey = KeysProvider.getMaskedSecret((BCECPrivateKey)key, r);
                SecureRandom rnd = getDetRND(secretKey);

                kpg.initialize(DILITHIUM_PARAM_SPEC, rnd);
                return kpg.generateKeyPair();
            } else {
                KeyFactory kf = KeyFactory.getInstance("EdDSA", "EdDSA");
                EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED_CURVE);

                byte[] secretKey;
                if (ED_RAND_SEED) {
                    Random r = new Random();
                    secretKey = KeysProvider.getMaskedSecret((BCECPrivateKey) key, r);
                } else {
                    secretKey = getBytes(((BCECPrivateKey) key).getD());
                }

                EdDSAPrivateKeySpec privKeySpec = new EdDSAPrivateKeySpec(secretKey, spec);
                PrivateKey privKey = kf.generatePrivate(privKeySpec);
                EdDSAPublicKeySpec pubKeySpec = new EdDSAPublicKeySpec(privKeySpec.getA(), spec);
                PublicKey pubkey = kf.generatePublic(pubKeySpec);

                return new KeyPair(pubkey, privKey);
            }
        } catch (Exception e) {
            logger.error("Failed creating key", e);
            return null;
        }
    }

    private static SecureRandom getDetRND(byte[] secretSeed) {
        Random r = new Random();
        r.setSeed(new BigInteger(1, secretSeed).longValue());

        //TODO: maybe private key storage. This deterministic key generation based on the weave private key of the signer is okish for now
        return KeysProvider.deterministicRandom(r);
    }

    public static AsymmetricCipherKeyPair deriveAccountRSAKeyPair(PrivateKey key) {
        try {
            byte[] secretKey;
            if (ED_RAND_SEED) {
                Random r = new Random();
                secretKey = KeysProvider.getMaskedSecret((BCECPrivateKey) key, r);
            } else {
                secretKey = getBytes(((BCECPrivateKey) key).getD());
            }

            SecureRandom rnd = getDetRND(secretKey);
            RSAKeyPairGenerator generator = new RSAKeyPairGenerator();
            generator.init(new RSAKeyGenerationParameters(RSA_PUBLIC_EXPONENT, rnd, RSA_STRENGTH, RSA_CERTAINTY));
            return generator.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed creating key", e);
            return null;
        }
    }

    //TODO: move
    public static String createAccountSignature(PrivateKey signerKey, byte[] toSign) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException  {
        if (signerKey instanceof DilithiumPrivateKey) {
            Signature signer = Signature.getInstance("Dilithium");

            signer.initSign(signerKey);

            signer.update(toSign);
            return Base58.encode(signer.sign());
        } else {
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(KeysProvider.ED_CURVE);
            Signature signer = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            //Signature signer = Signature.getInstance(KeysProvider.ED_CURVE);

            signer.initSign(signerKey);

            signer.update(toSign);
            return Base58.encode(signer.sign());
        }
    }

    public static PublicKey getAccountSigPublicKey(String signerKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        byte[] key = Base58.decode(signerKey);

        if (useDilithium && key.length > 1000) {
            KeyFactory kf = KeyFactory.getInstance("Dilithium");
            return kf.generatePublic(new DilithiumPublicKeySpec(DILITHIUM_PARAM_SPEC, key));
        } else {
            KeyFactory kf = KeyFactory.getInstance("EdDSA", "EdDSA");

            try {
                EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(key, EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
                return kf.generatePublic(spec);
            } catch (IllegalArgumentException e) {
                try {
                    KeysInfo keysInfo = KeysInfo.fromPublicKey(signerKey);
                    return keysInfo.getKeyPair().getPublic();
                } catch (Exception ex) {
                    logger.warn("Failed key decryption for " + signerKey, ex);
                    return null;
                }
            }
        }
    }

    public static boolean verifyAccountSignature(PublicKey signerKey, String signature, byte[] toCheck) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (signerKey instanceof BCEdDSAPublicKey) {
            //Signature signer = EdDSAEngine.getInstance(KeysProvider.ED_CURVE);
            Signature signer = Signature.getInstance(KeysProvider.ED_CURVE);
            signer.initVerify(signerKey);

            //TODO: make sure we are standard conformant https://w3c-ccg.github.io/lds-ed25519-2020/#dfn-ed25519signature2020
            signer.update(toCheck);
            return signer.verify(Base58.decode(signature));
        } else if (signerKey instanceof DilithiumPublicKey) {
            Signature sigVerify = Signature.getInstance("Dilithium");
            sigVerify.initVerify(signerKey);
            sigVerify.update(toCheck);
            return sigVerify.verify(Base58.decode(signature));
        } else {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initVerify(signerKey);
            sgr.update(toCheck);

            byte[] sig = Base58.decode(signature);
            return sgr.verify(sig);
        }
    }

    public static boolean verifyAccountSignature(String signerKey, String signature, byte[] toCheck) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        byte[] key = Base58.decode(signerKey);
        byte[] sig = Base58.decode(signature);

        if (key.length < 1024) { //TODO: smarter check? //if (USE_DILITHIUM)
            KeyFactory kf = KeyFactory.getInstance("EdDSA", "EdDSA");
            EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(key, EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
            PublicKey sigKey = kf.generatePublic(spec);

            Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
            sgr.initVerify(sigKey);
            sgr.update(toCheck);

            return sgr.verify(sig);
        } else {
            KeyFactory kf = KeyFactory.getInstance("Dilithium");
            PublicKey serializedKey = kf.generatePublic(new DilithiumPublicKeySpec(DILITHIUM_PARAM_SPEC, key));

            Signature sgr = Signature.getInstance("Dilithium");
            sgr.initVerify(serializedKey);
            sgr.update(toCheck);

            return sgr.verify(sig);
        }
    }

    public static KeyPair generateEd25519KeyPair(byte[] seed) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(ED_CURVE);
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(ED_CURVE);

            SecureRandom rnd = SecureRandom.getInstanceStrong();
            rnd.setSeed(seed);
            kpg.initialize(spec, rnd);

            return kpg.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed creating key", e);
            return null;
        }
    }

    public static byte[] generateIV() {
        return generateIV(16);
    }

    public static byte[] generateIV(int len) {
        byte[] iv = new byte[len];
        RND.nextBytes(iv);
        return iv;
    }

    public static KeyPair deriveSphincsKeyPair(PrivateKey key) {
        try {
            Random r = new Random();
            byte[] secretKey = KeysProvider.getMaskedSecret((BCECPrivateKey)key, r);
            SecureRandom rnd = getDetRND(secretKey);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SPHINCS256", POST_QUANTUM_PROVIDER);
            kpg.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA3_256), rnd);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            logger.error("Failed initializing key", e);
            return null;
        }
    }

    public static SecureRandom deterministicRandom(Random r) {
        SecureRandom rnd = new SecureRandom() {
            public String getAlgorithm() {
                return "insecure";
            }

            public void setSeed(byte[] seed) {
            }

            public void setSeed(long seed) {
            }

            public void nextBytes(byte[] bytes) {
                r.nextBytes(bytes);
            }

            public byte[] generateSeed(int numBytes) {
                byte[] seed = new byte[numBytes];
                r.nextBytes(seed);
                return seed;
            }

            public int nextInt() {
                return r.nextInt();
            }

            public int nextInt(int n) {
                return r.nextInt(n);
            }

            public boolean nextBoolean() {
                return r.nextBoolean();
            }

            public long nextLong() {
                return r.nextLong();
            }

            public float nextFloat() {
                return r.nextFloat();
            }

            public double nextDouble() {
                return r.nextDouble();
            }

            public double nextGaussian() {
                return r.nextGaussian();
            }
        };
        return rnd;
    }

    public static byte[] getMaskedSecret(BCECPrivateKey key, Random r) {
        byte[] seed = KeysProvider.getBytes(key.getD().toByteArray(), 32);
        long value = 0;
        int off = seed.length == 33 ? 1 : 0;
        for (int i = off; i < 6 + off; i++) {
            value = value * 256 + (seed[i] < 0 ? 256 + seed[i] : seed[i]);
        }
        r.setSeed(value);
        byte[] secretKey = new byte[32];
        r.nextBytes(secretKey);
        for (int i = 0; i < 32; i++) {
            secretKey[i] ^= seed[i + off];
        }
        return secretKey;
    }

    public static void main(String[] args) {
        KeyPair serverKeys = KeysProvider.getInstance().generateKeys();
        String publicKey = KeysProvider.getBase58Key(serverKeys.getPublic());
        String privateKey = KeysProvider.getBase58Key(serverKeys.getPrivate());

        System.out.println("\nGenerated key:");
        System.out.println(publicKey);
        System.out.println(privateKey);
    }
}
