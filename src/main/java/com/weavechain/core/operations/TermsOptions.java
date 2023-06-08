package com.weavechain.core.operations;

import com.google.gson.*;
import com.weavechain.core.data.ConvertUtils;
import com.weavechain.core.encoding.Utils;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.lang.reflect.Type;
import java.util.Map;

@Getter
@AllArgsConstructor
public class TermsOptions {

    private Boolean agreeTerms;

    private Boolean agreePrivacyPolicy;

    public static class Serializer implements JsonSerializer<TermsOptions> {
        public JsonElement serialize(TermsOptions data, Type typeOfSrc, JsonSerializationContext context) {
            JsonObject element = new JsonObject();
            element.add("agreeTerms", new JsonPrimitive(data.getAgreeTerms()));
            element.add("agreePrivacyPolicy", new JsonPrimitive(data.getAgreePrivacyPolicy()));
            return element;
        }
    }

    @SuppressWarnings("unchecked")
    public static TermsOptions fromObject(Object options) {
        if (options instanceof String) {
            return Utils.getGson().fromJson(options.toString(), TermsOptions.class);
        } else if (options instanceof Map) {
            Map data = (Map)options;
            return new TermsOptions(
                    ConvertUtils.convertToBoolean(data.get("agreeTerms"), DISAGREE.getAgreeTerms()),
                    ConvertUtils.convertToBoolean(data.get("agreePrivacyPolicy"), DISAGREE.getAgreeTerms())
            );
        } else {
            return TermsOptions.DISAGREE;
        }
    }

    public static TermsOptions AGREE = new TermsOptions(
            true,
            true
    );

    public static TermsOptions DISAGREE = new TermsOptions(
            false,
            false
    );
}