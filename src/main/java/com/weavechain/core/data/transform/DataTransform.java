package com.weavechain.core.data.transform;

public enum DataTransform {

    NONE,

    ERASURE,            //field value is blanked. Nulls and data type are preserved

    REDACTION,          //field value is replaced. Nulls and data type are preserved

    HASHING,            //field value is hashed (SHA2). Nulls are preserved, result data type is string

    RANDOM_ID,          //field value is associated a random id. Nulls are preserved, result data type is long

    LINKED_RANDOM_ID,   //field value is associated a random id. Nulls are preserved, result data type is long. Same id mapped to the same value in all tables

    NOISE_ADDITION,    //needs private params configuration

    QUANTIZATION,       //needs private params configuration

    ENCRYPT,            //needs private params configuration

    //NULLING,          //partial clear, needs knowledge about the field structure

    //MASKING,          //needs knowledge about the field structure

    //SYNTHETIC         //needs knowledge about the field structure and distribution

    //Others: transform data to give k-anonymity guarantees

    //TODO: review, maybe move from here and add a generic transformation layer
    CONVERT_LONG,       //not an actual obfuscation, convenience helper for transforming string timestamps, converting them to ms since epoch
    CONVERT_DOUBLE      //similar, converting to seconds since epoch and ms in the fractional part

}