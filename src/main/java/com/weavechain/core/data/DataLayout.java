package com.weavechain.core.data;

import com.weavechain.core.data.transform.*;
import com.weavechain.core.encoding.Utils;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.function.Supplier;

public class DataLayout {

    static final Logger logger = LoggerFactory.getLogger(DataLayout.class);

    public static final DataLayout DEFAULT = createDefault();

    private transient Map<DataTransform, Transformation> transformationAlgo;

    private final Map<String, DataType> layout = new LinkedHashMap<>();

    private final Map<String, Integer> indexes = new LinkedHashMap<>();

    private final List<String> columnNames = new ArrayList<>();

    private final List<DataColumn> columns = new ArrayList<>();

    @Getter
    private final Integer idColumnIndex;

    @Getter
    private final Integer timestampColumnIndex;

    @Getter
    private final Integer ownerColumnIndex;

    @Getter
    private final Integer signatureColumnIndex;

    @Getter
    private final Integer sourceIpColumnIndex;

    @Getter
    private final Integer allowedRolesColumnIndex;

    @Getter
    private final String ownerReadFilter;

    @Getter
    private final Integer encryptSaltColumnIndex;

    @Getter
    private final Integer updateProofColumnIndex;

    @Getter
    private final boolean isLocal;

    @Getter
    private final boolean isOnlyOwnDataAllowed;

    @Getter
    private final boolean applyReadTransformations;

    @Getter
    private final boolean allowEndingNulls;

    @Getter
    private final boolean autoUpdated;

    @Getter
    private final boolean autoUpdatable;

    @Getter
    private transient Boolean hasEncryptedColumns = null;

    private static Map<String, Map<String, TransformationAlgoParams>> transformAlgoParams; //Needed only server side. TODO: revisit, ugly injection

    public DataLayout(Integer idColumnIndex, Integer timestampColumnIndex) {
        this(idColumnIndex, timestampColumnIndex, null, null, null, null, null, null, null, false, false, true, true, false, true);
    }

    public DataLayout(Integer idColumnIndex, Integer timestampColumnIndex, boolean autoUpdated) {
        this(idColumnIndex, timestampColumnIndex, null, null, null, null, null, null, null, false, false, true, true, autoUpdated, true);
    }

    public DataLayout(Integer idColumnIndex, Integer timestampColumnIndex, Integer ownerColumnIndex, Integer signatureColumnIndex, Integer sourceIpColumnIndex, Integer allowedRolesColumnIndex, String ownerReadFilter, Integer encryptSaltColumnIndex, Integer updateProofColumnIndex) {
        this(idColumnIndex, timestampColumnIndex, ownerColumnIndex, signatureColumnIndex, sourceIpColumnIndex, allowedRolesColumnIndex, ownerReadFilter, encryptSaltColumnIndex, updateProofColumnIndex, false, false, true, true, false, true);
    }

    public DataLayout(
            Integer idColumnIndex,
            Integer timestampColumnIndex,
            Integer ownerColumnIndex,
            Integer signatureColumnIndex,
            Integer sourceIpColumnIndex,
            Integer allowedRolesColumnIndex,
            String ownerReadFilter,
            Integer encryptSaltColumnIndex,
            Integer updateProofColumnIndex,
            boolean isLocal,
            boolean isOnlyOwnDataAllowed,
            boolean applyReadTransformations,
            boolean allowEndingNulls,
            boolean autoUpdated,
            boolean autoUpdatable
    ) {
        this.idColumnIndex = idColumnIndex;
        this.timestampColumnIndex = timestampColumnIndex;
        this.ownerColumnIndex = ownerColumnIndex;
        this.signatureColumnIndex = signatureColumnIndex;
        this.sourceIpColumnIndex = sourceIpColumnIndex;
        this.allowedRolesColumnIndex = allowedRolesColumnIndex;
        this.ownerReadFilter = ownerReadFilter;
        this.encryptSaltColumnIndex = encryptSaltColumnIndex;
        this.updateProofColumnIndex = updateProofColumnIndex;
        this.isLocal = isLocal;
        this.isOnlyOwnDataAllowed = isOnlyOwnDataAllowed;
        this.allowEndingNulls = allowEndingNulls;
        this.autoUpdated = autoUpdated;
        this.autoUpdatable = autoUpdatable;

        this.applyReadTransformations = applyReadTransformations;

        buildTransformationsMap();
    }

    public static void setTransformAlgoParams(Map<String, Map<String, TransformationAlgoParams>> value) {
        transformAlgoParams = value != null ? new HashMap<>(value) : null;
    }

    public static TransformationAlgoParams getTransformAlgoParams(String scope, String table) {
        if (transformAlgoParams != null && transformAlgoParams.get(scope) != null) {
            return transformAlgoParams.get(scope).get(table);
        } else {
            return null;
        }
    }

    private void buildTransformationsMap() {
        transformationAlgo = new HashMap<>();

        transformationAlgo.put(DataTransform.ERASURE, new Erasure());
        transformationAlgo.put(DataTransform.REDACTION, new Redaction());
        transformationAlgo.put(DataTransform.HASHING, new Hashing(MappingRepositories.INSTANCE.getHashesRepository()));
        transformationAlgo.put(DataTransform.RANDOM_ID, new RandomId(MappingRepositories.INSTANCE.getRandomIdsRepository()));
        transformationAlgo.put(DataTransform.LINKED_RANDOM_ID, new RandomId(MappingRepositories.INSTANCE.getLinkedRandomIdsRepository()));

        transformationAlgo.put(DataTransform.NOISE_ADDITION, new NoiseAdded());
        transformationAlgo.put(DataTransform.ENCRYPT, new Encrypt());
        transformationAlgo.put(DataTransform.QUANTIZATION, new Quantization());

        transformationAlgo.put(DataTransform.CONVERT_LONG, new ConvertLong());
        transformationAlgo.put(DataTransform.CONVERT_DOUBLE, new ConvertDouble());
    }

    public void addColumns(DataLayout other) {
        for (int i = 0; i < other.size(); i++) {
            DataColumn column = other.getDefinition(i);
            add(column.getColumnName(),
                    column.getType(),
                    column.getReadTransform(),
                    column.getDefaultValue(),
                    column.isIndexed(),
                    column.isNullable(),
                    column.isUnique(),
                    column.isEncrypted(),
                    column.isAllowPlaintext()
            );
        }
    }

    public String add(
            String columnName,
            DataType type,
            DataTransform readTransform,
            Supplier<Object> defaultValue,
            boolean isIndexed,
            boolean isNullable,
            boolean isUnique,
            boolean isEncrypted,
            boolean allowPlaintext
    ) {
        String name = Utils.sanitizeSQL(columnName);

        if (!layout.containsKey(name)) {
            hasEncryptedColumns = null;
            indexes.put(name, columnNames.size());
            columnNames.add(name);
            columns.add(new DataColumn(
                    name,
                    type,
                    readTransform,
                    isIndexed,
                    isNullable,
                    isUnique,
                    isEncrypted,
                    allowPlaintext,
                    defaultValue
            ));

            layout.put(name, type);
            return name;
        } else {
            logger.error("Column already exists, using previous definition");
            return null;
        }
    }

    public DataType getType(String column) {
        return layout.get(column);
    }

    public Integer getIndex(String column) {
        return indexes.get(column);
    }

    public String getColumn(int index) {
        return columnNames.get(index);
    }

    public DataColumn getDefinition(int index) {
        return columns.get(index);
    }

    public DataType getType(int index) {
        DataColumn column = columns.get(index);
        return column.getType();
    }

    public DataType getStorageType(int index) {
        DataColumn column = columns.get(index);
        return column.isEncrypted() ? DataType.STRING : column.getType();
    }

    public DataTransform getTransform(int index) {
        DataColumn column = columns.get(index);
        return column.getReadTransform();
    }

    public Object getDefaultValue(int index) {
        DataColumn column = columns.get(index);
        return column.getDefaultValue() != null ? column.getDefaultValue().get() : null;
    }

    public String[] getColumnNames() {
        return columnNames.toArray(new String[0]);
    }

    public String[] getColumnNames(int count) {
        return columnNames.subList(0, count).toArray(new String[0]);
    }

    public int size() {
        return layout.size();
    }

    public Object transform(String scope, String table, int index, Object value) {
        if (applyReadTransformations) {
            DataTransform type = getTransform(index);
            Transformation transformation = type != null ? getTransformationAlgo(type) : null;

            try {
                if (transformation != null) {
                    return transformation.transform(scope, table, value);
                } else {
                    return value;
                }
            } catch (Exception e) {
                logger.error("Failed transformation", e);
                return null;
            }
        } else {
            return value;
        }
    }

    private Transformation getTransformationAlgo(DataTransform type) {
        if (transformationAlgo == null) {
            buildTransformationsMap();
        }

        return transformationAlgo.get(type);
    }

    public void applyDataTransformations(String scope, String table, List<Map<String, Object>> result) {
        if (applyReadTransformations) {
            Integer idColIdx = getIdColumnIndex();
            for (int i = 0; i < size(); i++) {
                if (idColIdx == null || i != idColIdx) {
                    DataTransform type = getTransform(i);
                    Transformation transformation = type != null ? getTransformationAlgo(type) : null;

                    if (transformation != null) {
                        String column = getColumn(i);

                        for (Map<String, Object> it : result) {
                            Object value = it.get(column);
                            try {
                                it.put(column, transformation.transform(scope, table, value));
                            } catch (Exception e) {
                                logger.error("Failed transformation", e);
                                it.put(column, null);
                            }
                        }
                    }
                }
            }
        }
    }

    public void applyDataTransformations(String scope, String table, Records records) {
        if (applyReadTransformations) {
            Integer idColIdx = getIdColumnIndex();
            for (int i = 0; i < size(); i++) {
                if (idColIdx == null || i != idColIdx) {
                    DataTransform type = getTransform(i);
                    Transformation transformation = type != null ? getTransformationAlgo(type) : null;

                    if (transformation != null) {
                        String column = getColumn(i);

                        for (List<Object> item : records.getItems()) {
                            Object value = item.get(i);
                            try {
                                item.set(i, transformation.transform(scope, table, value));
                            } catch (Exception e) {
                                logger.error("Failed transformation", e);
                                item.set(i, null);
                            }
                        }
                    }
                }
            }
        }
    }

    public Long getId(List<Object> record) {
        if (idColumnIndex != null) {
            //TODO: modify callers to support listener pattern non-numeric IDs
            return ConvertUtils.convertToLong(record.get(idColumnIndex));
        } else {
            throw new IllegalArgumentException("No ID column defined");
        }
    }

    public void copyColumns(DataLayout targetLayout) {
        for (int i = 0; i < size(); i++) {
            DataColumn col = getDefinition(i);
            targetLayout.add(
                    col.getColumnName(),
                    col.getType(),
                    col.getReadTransform(),
                    col.getDefaultValue(),
                    col.isIndexed(),
                    col.isNullable(),
                    col.isUnique(),
                    col.isEncrypted(),
                    col.isAllowPlaintext()
            );
        }
    }

    public static DataLayout createDefault() {
        DataLayout layout = new DataLayout(0, 3, null, null, null, null, null, null, null);
        layout.add("id", DataType.LONG, DataTransform.NONE, null, true, false, true, false, true);
        layout.add("data", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("metadata", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("ts", DataType.LONG, DataTransform.NONE, System::currentTimeMillis, true, true, false, false, true); //Will be replaced by network time
        return layout;
    }

    public static DataLayout createDefaultWithOwner() {
        DataLayout layout = new DataLayout(0, 3, 4, 5, null, null, null, null, null);
        layout.add("id", DataType.LONG, DataTransform.NONE, null, true, false, true, false, true);
        layout.add("data", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("metadata", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("ts", DataType.LONG, DataTransform.NONE, System::currentTimeMillis, true, true, false, false, true); //Will be replaced by network time
        layout.add("owner", DataType.STRING, DataTransform.NONE, null, true, true, false, false, true);
        layout.add("signature", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        return layout;
    }

    public static DataLayout createDefaultWithOwnerAndRoles() {
        DataLayout layout = new DataLayout(0, 3, 4, 5, null, 6, null, null, null);
        layout.add("id", DataType.LONG, DataTransform.NONE, null, true, false, true, false, true);
        layout.add("data", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("metadata", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("ts", DataType.LONG, DataTransform.NONE, System::currentTimeMillis, true, true, false, false, true); //Will be replaced by network time
        layout.add("owner", DataType.STRING, DataTransform.NONE, null, true, true, false, false, true);
        layout.add("signature", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        layout.add("roles", DataType.STRING, DataTransform.NONE, null, false, true, false, false, true);
        return layout;
    }

    public boolean hasEncryptedColumns() {
        if (hasEncryptedColumns == null) {
            boolean res = false;
            for (DataColumn col : columns) {
                if (col.isEncrypted()) {
                    res = true;
                    break;
                }
            }
            hasEncryptedColumns = res;
        }

        return hasEncryptedColumns;
    }

    //TODO: change serialization, the current representation is suboptimal
    public String toJson() {
        return Utils.getGson().toJson(this);
    }

    public static DataLayout fromJson(String data) {
        return data != null && !data.isEmpty() ? Utils.getGson().fromJson(data, DataLayout.class) : null;
    }


    public static DataLayout unpackLayout(Map<String, Object> data) {
        DataLayout layout = DataLayout.DEFAULT;
        if (data.get("layout") != null) {
            Map<String, Object> items = data.get("layout") instanceof String ? Utils.getGson().fromJson((String) data.get("layout"), Map.class) : (Map<String, Object>) data.get("layout");

            Integer idColumn = null;
            if (items.get("idColumnIndex") != null) {
                idColumn = ConvertUtils.convertToLong(items.get("idColumnIndex")).intValue();
            } else {
                idColumn = new ArrayList<>(items.keySet()).indexOf("id");
                if (idColumn < 0) {
                    idColumn = null;
                }
            }
            Integer idColumnIndex = idColumn;
            Integer timestampColumnIndex = items.get("timestampColumnIndex") != null ? ConvertUtils.convertToLong(items.get("timestampColumnIndex")).intValue() : null;
            Integer ownerColumnIndex = items.get("ownerColumnIndex") != null ? ConvertUtils.convertToLong(items.get("ownerColumnIndex")).intValue() : null;
            Integer signatureColumnIndex = items.get("signatureColumnIndex") != null ? ConvertUtils.convertToLong(items.get("signatureColumnIndex")).intValue() : null;
            Integer sourceIpColumnIndex = items.get("sourceIpColumnIndex") != null ? ConvertUtils.convertToLong(items.get("sourceIpColumnIndex")).intValue() : null;
            if (sourceIpColumnIndex == null) {
                sourceIpColumnIndex = items.get("sourceIPColumnIndex") != null ? ConvertUtils.convertToLong(items.get("sourceIPColumnIndex")).intValue() : null;
            }
            Integer allowedRolesColumnIndex = items.get("allowedRolesColumnIndex") != null ? ConvertUtils.convertToLong(items.get("allowedRolesColumnIndex")).intValue() : null;
            String ownerReadFilter = items.get("ownerReadFilter") != null ? ConvertUtils.convertToString(items.get("ownerReadFilter")) : null;
            Integer encryptSaltColumnIndex = items.get("encryptSaltColumnIndex") != null ? ConvertUtils.convertToLong(items.get("encryptSaltColumnIndex")).intValue() : null;
            Integer updateProofColumnIndex = items.get("updateProofColumnIndex") != null ? ConvertUtils.convertToLong(items.get("updateProofColumnIndex")).intValue() : null;

            Boolean isLocal = ConvertUtils.convertToBoolean(items.get("isLocal"));
            Boolean isOnlyOwnDataAllowed = ConvertUtils.convertToBoolean(items.get("isOnlyOwnDataAllowed"));
            Boolean applyReadTransformations = ConvertUtils.convertToBoolean(items.get("applyReadTransformations"));
            Boolean allowEndingNulls = ConvertUtils.convertToBoolean(items.get("allowEndingNulls"));
            Boolean autoUpdated = ConvertUtils.convertToBoolean(items.get("autoUpdated"));
            boolean autoUpdatable = items.get("autoUpdatable") == null || ConvertUtils.convertToBoolean(items.get("autoUpdatable"));

            layout = new DataLayout(
                    idColumnIndex,
                    timestampColumnIndex,
                    ownerColumnIndex,
                    signatureColumnIndex,
                    sourceIpColumnIndex,
                    allowedRolesColumnIndex,
                    ownerReadFilter,
                    encryptSaltColumnIndex,
                    updateProofColumnIndex,
                    isLocal != null && isLocal,
                    isOnlyOwnDataAllowed != null && isOnlyOwnDataAllowed,
                    applyReadTransformations == null || applyReadTransformations,
                    allowEndingNulls == null || allowEndingNulls,
                    autoUpdated != null && autoUpdated,
                    autoUpdatable
            );

            if (items.get("columns") instanceof Map) {
                Map<String, Map<String, Object>> columns = (Map<String, Map<String, Object>>) items.get("columns");
                for (Map.Entry<String, Map<String, Object>> col : columns.entrySet()) {
                    Map<String, Object> colData = col.getValue();
                    addColumn(layout, col.getKey(), colData);
                }
            } else if (items.get("columns") instanceof List) {
                List<Map<String, Object>> columns = (List<Map<String, Object>>) items.get("columns");
                for (Map<String, Object> colData : columns) {
                    addColumn(layout, (String)colData.get("columnName"), colData);
                }
            }
        }
        return layout;
    }

    private static void addColumn(DataLayout layout, String colName, Map<String, Object> colData) {
        DataType type = DataType.valueOf(colData.get("type").toString());
        DataTransform readTransform = colData.get("readTransform") != null ? DataTransform.valueOf(colData.get("readTransform").toString()) : DataTransform.NONE;
        Supplier<Object> defaultValue = null;

        //TODO: move defaults to config
        Boolean isIndexed = ConvertUtils.convertToBoolean(colData.get("isIndexed"), false);
        Boolean isNullable = ConvertUtils.convertToBoolean(colData.get("isNullable"), true);
        Boolean isUnique = ConvertUtils.convertToBoolean(colData.get("isUnique"), false);
        Boolean isEncrypted = ConvertUtils.convertToBoolean(colData.get("isEncrypted"), false);
        Boolean allowPlaintext = ConvertUtils.convertToBoolean(colData.get("allowPlaintext"), true);

        layout.add(
                colName,
                type,
                readTransform,
                defaultValue,
                isIndexed,
                isNullable,
                isUnique,
                isEncrypted,
                allowPlaintext
        );
    }

    public boolean sameColumns(DataLayout other) {
        if (other == null) {
            return false;
        }

        return this.columnNames.containsAll(other.columnNames)
                && other.columnNames.containsAll(this.columnNames);
    }
}