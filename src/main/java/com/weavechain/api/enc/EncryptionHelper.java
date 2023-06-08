package com.weavechain.api.enc;

import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.data.DataColumn;
import com.weavechain.core.data.DataLayout;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.EncryptionConfig;
import com.weavechain.core.encrypt.FieldEncrypt;
import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

public class EncryptionHelper {

    //TODO: optimize

    private static final Map<String, FieldEncrypt> encryptors = Utils.newConcurrentHashMap();

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public static void encryptRecords(DataLayout layout, EncryptionConfig config, List<List<Object>> result) {
        if (layout != null && layout.hasEncryptedColumns() && result != null && config != null && !EncryptionConfig.NONE.equals(config.getType())) {
            for (List<Object> row: result) {
                String salt = null;
                if (layout.getEncryptSaltColumnIndex() != null) {
                    byte[] r = new byte[16];
                    RANDOM.get().nextBytes(r);
                    salt = Base64.encodeBase64String(r);
                    row.set(layout.getEncryptSaltColumnIndex(), salt);
                }

                for (int i = 0; i < layout.size(); i++) {
                    DataColumn col = layout.getDefinition(i);
                    if (col.isEncrypted()) {

                        FieldEncrypt enc = getFieldEncrypt(config, salt);

                        row.set(i, enc.encrypt(row.get(i)));
                    }
                }
            }
        }
    }

    public static void decryptRecord(DataLayout layout, EncryptionConfig config, Map<String, Object> row) {
        if (layout != null && layout.hasEncryptedColumns() && row != null && config != null && !EncryptionConfig.NONE.equals(config.getType())) {
            String salt = null;
            if (layout.getEncryptSaltColumnIndex() != null && layout.getEncryptSaltColumnIndex() < row.size()) {
                salt = ConvertUtils.convertToString(row.get(layout.getColumn(layout.getEncryptSaltColumnIndex())));
            }

            FieldEncrypt enc = getFieldEncrypt(config, salt);

            for (int i = 0; i < layout.size(); i++) {
                DataColumn col = layout.getDefinition(i);
                if (col.isEncrypted()) {
                    Object val = enc.decrypt(row.get(col.getColumnName()));
                    row.put(col.getColumnName(), ConvertUtils.convert(val, layout.getType(i)));
                }
            }
        }
    }

    public static void decryptRecord(DataLayout layout, EncryptionConfig config, List<Object> row) {
        if (layout != null && layout.hasEncryptedColumns() && row != null && config != null && !EncryptionConfig.NONE.equals(config.getType())) {
            String salt = null;
            if (layout.getEncryptSaltColumnIndex() != null && layout.getEncryptSaltColumnIndex() < row.size()) {
                salt = ConvertUtils.convertToString(row.get(layout.getEncryptSaltColumnIndex()));
            }

            FieldEncrypt enc = getFieldEncrypt(config, salt);

            for (int i = 0; i < layout.size(); i++) {
                DataColumn col = layout.getDefinition(i);
                if (col.isEncrypted()) {
                    Object val = enc.decrypt(row.get(i));
                    row.set(i, ConvertUtils.convert(val, layout.getType(i)));
                }
            }
        }
    }

    public static void decryptRecords(DataLayout layout, EncryptionConfig config, List<Map<String, Object>> result) {
        if (result != null && config != null && !EncryptionConfig.NONE.equals(config.getType())) {
            for (Map<String, Object> item : result) {
                decryptRecord(layout, config, item);
            }
        }
    }

    private static FieldEncrypt getFieldEncrypt(EncryptionConfig config, String salt) {
        String key = config.getType() + ":" + config.getSecretKey() + ":" + (salt != null ? salt : ""); //TODO: need to drop this from the map key
        return encryptors.computeIfAbsent(key, (k) -> {
            FieldEncrypt e = FieldEncrypt.getEncryptor(config.getType());
            e.init(config.getSecretKey(), salt != null && salt.length() > 0 ? salt : config.getSalt());
            return e;
        });
    }
}