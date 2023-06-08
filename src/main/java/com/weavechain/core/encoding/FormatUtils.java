package com.weavechain.core.encoding;

import java.time.format.DateTimeFormatter;

public class FormatUtils {

    public final static String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss[.SSSSSS][.SSSSS][.SSSS][.SSS][.SS][.S]";

    public final static String ISO_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss[.SSSSSS][.SSSSS][.SSSS][.SSS][.SS][.S][Z]";

    public final static String ISO_DATE_FORMAT_OFFSET = "yyyy-MM-dd'T'HH:mm:ss[.SSSSSS][.SSSSS][.SSSS][.SSS][.SS][.S][xxx][xx][X]";

    public final static String DATE_FORMAT_OUT = "yyyy-MM-dd HH:mm:ss.SSS";

    public final static String DATE_FORMAT_OUT_SEC = "yyyy-MM-dd HH:mm:ss";

    public final static String DAY_FORMAT = "yyyy-MM-dd";

    public static ThreadLocal<DateTimeFormatter> FMT_DATE_FORMAT = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(DATE_FORMAT);
        }
    };

    public static ThreadLocal<DateTimeFormatter> FMT_DAY_FORMAT = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(DAY_FORMAT);
        }
    };

    public static ThreadLocal<DateTimeFormatter> FMT_ISO_DATE_FORMAT = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(ISO_DATE_FORMAT);
        }
    };

    public static ThreadLocal<DateTimeFormatter> FMT_ISO_DATE_FORMAT_OFFSET = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(ISO_DATE_FORMAT_OFFSET);
        }
    };

    public static ThreadLocal<DateTimeFormatter> FMT_DATE_FORMAT_OUT = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(DATE_FORMAT_OUT);
        }
    };

    public static ThreadLocal<DateTimeFormatter> FMT_DATE_FORMAT_OUT_SEC = new ThreadLocal<DateTimeFormatter>() {
        @Override
        protected DateTimeFormatter initialValue() {
            return DateTimeFormatter.ofPattern(DATE_FORMAT_OUT_SEC);
        }
    };
}