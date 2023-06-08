package com.weavechain.core.operations;

import com.weavechain.core.data.filter.Filter;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.error.OperationResult;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
public class ReadContext {

    static final Logger logger = LoggerFactory.getLogger(ReadContext.class);

    public static final ReadContext NULL_INSTANCE = new ReadContext(null, null, null, null, null, null);

    private final ReadOptions options;

    private final Filter filter;

    private final String organization;

    private final String actualReader;

    private Object data;

    private OperationResult mergedResult;

    private String wallet;

    private List<Map<String, Object>> credentials;

    public ReadContext(ReadOptions options, Filter filter, String organization, String actualReader, String wallet, String credentials) {
        this.options = options;
        this.filter = filter;
        this.data = null;
        this.organization = organization;
        this.actualReader = actualReader;
        this.wallet = wallet;

        if (credentials != null) {
            this.credentials = parseCredentials(credentials);
        }
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> parseCredentials(String credentials) {
        List<Map<String, Object>> result = new ArrayList<>();
        try {
            try {
                Map<String, Object> vc = Utils.getGson().fromJson(credentials, Map.class);
                if (vc != null) {
                    result.add(vc);
                }
            } catch (Exception e) {
                List<Map<String, Object>> cred = Utils.getGson().fromJson(credentials, List.class);
                result.addAll(cred);
            }

            return result;
        } catch (Exception e) {
            logger.error("Failed parsing credentials");
            return result;
        }
    }

    public boolean ackData(OperationResult result) {
        if (result.isError()) {
            //TODO: merge errors
            mergedResult = result;
        }
        data = result.getData();
        return !options.isVerifyHash();
    }

    public boolean ackHash(OperationResult result) {
        return true;
    }
}