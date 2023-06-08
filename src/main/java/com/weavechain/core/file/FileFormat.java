package com.weavechain.core.file;

public enum FileFormat {

    //TODO: add ORC support

    //generic unformatted file (limited functionality)
    file,

    //raw (uncompressed) binary encoding of records
    raw,

    //raw (uncompressed) binary encoding, one file per record.
    //   Can be used with multiple columns, only one STRING as last column, but original intent is to publish image files as a single base64 encoded field
    encoded_file,

    csv,

    avro,

    //TODO: identify when append is happening and throw error OR re-generate to support append
    json,

    parquet,

    feather,

    orc,

    toml,

    yaml,

    protobuf

    //TODO: folder //this is important for ML datasets and needs updates and lineage treate separately in a special way
}