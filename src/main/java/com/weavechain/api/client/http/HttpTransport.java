package com.weavechain.api.client.http;

import com.weavechain.api.config.transport.HttpClientConfig;
import com.weavechain.api.session.Session;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.encrypt.Hash;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.HttpHostConnectException;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HTTP;
import org.apache.http.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Map;
import java.util.function.Consumer;

public class HttpTransport {

    private static final int CONNECTION_TIMEOUT = 60;

    private static final int RETRIES = 100;

    private static final int THROTTLE_MS = 1000;

    static final Logger logger = LoggerFactory.getLogger(HttpTransport.class);

    private final SSLContext sslContext;

    public HttpTransport(HttpClientConfig config) {
        this.sslContext = createSSLContext(config);
    }

    SSLContext createSSLContext(HttpClientConfig config) {
        if (config.isUseHttps() && config.getKeyStore() != null) {
            try {
                KeyStore ks = KeyStore.getInstance("JKS");
                File kf = new File(config.getKeyStore());
                ks.load(new FileInputStream(kf), config.getKeyStorePass().toCharArray());

                return SSLContexts.custom()
                        .loadKeyMaterial(ks, config.getKeyStorePass() != null ? config.getKeyStorePass().toCharArray() : null)
                        .build();
            } catch (Exception e) {
                logger.error("Failed reading keystore", e);
                return null;
            }
        } else {
            return null;
        }
    }

    private CloseableHttpClient getHttpClient() {
        HttpClientBuilder httpClient = HttpClients.custom();
        if (sslContext != null) {
            httpClient.setSSLContext(sslContext);
        }
        return httpClient.build();
    }

    public HttpReply syncGet(String url) {
        try {
            CloseableHttpClient httpClient = getHttpClient();
            HttpGet request = new HttpGet(url);
            request.addHeader(HTTP.CONTENT_ENCODING, "gzip");

            int nTry = 0;
            while (nTry < RETRIES) {
                try {
                    CloseableHttpResponse response = httpClient.execute(request);

                    int statusCode = response.getStatusLine().getStatusCode();
                    byte[] data = response.getEntity().getContent().readAllBytes();
                    String body = new String(data, StandardCharsets.UTF_8);
                    return new HttpReply(statusCode, body, response.getAllHeaders());
                } catch (Exception e) {
                    try {
                        Thread.sleep((int) (THROTTLE_MS + (nTry > 10 ? Math.sqrt(nTry) * 500 : 0)));
                    } catch (InterruptedException ex) {
                    }
                    if (e instanceof HttpHostConnectException) {
                        logger.warn("Waiting for connection...");
                    } else {
                        logger.warn("Failed connecting", e);
                    }
                    nTry++;
                }
            }
            logger.error("Failed connecting, giving up");
            return null;
        } catch (Exception e) {
            logger.error("Failed API call", e);
            return null;
        }
    }

    public HttpReply syncDownload(String url, int bufferSize, Consumer<byte[]> callback) {
        CloseableHttpClient httpClient = getHttpClient();
        HttpGet request = new HttpGet(url);
        request.addHeader(HTTP.CONTENT_ENCODING, "gzip");

        try {
            CloseableHttpResponse response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();
            InputStream content = response.getEntity().getContent();
            byte[] data;
            if (statusCode == 200) {
                do {
                    data = content.readNBytes(bufferSize);
                    if (data.length > 0) {
                        callback.accept(data);
                    }
                } while (data.length > 0);

                return new HttpReply(statusCode, "", response.getAllHeaders());
            } else {
                data = content.readAllBytes();
                String body = new String(data, StandardCharsets.UTF_8);
                return new HttpReply(statusCode, body, response.getAllHeaders());
            }
        } catch (Exception e) {
            logger.warn("Failed connecting", e);
            return null;
        }
    }

    public HttpReply syncDownloadPost(String url, Map<String, Object> params, int bufferSize, Consumer<byte[]> callback) {
        try {
            CloseableHttpClient httpClient = getHttpClient();
            HttpPost request = new HttpPost(url);
            request.addHeader(HTTP.CONTENT_ENCODING, "gzip");
            request.setEntity(new StringEntity(Utils.getGson().toJson(params)));
            CloseableHttpResponse response = httpClient.execute(request);

            int statusCode = response.getStatusLine().getStatusCode();
            InputStream content = response.getEntity().getContent();
            byte[] data;
            if (statusCode == 200) {
                do {
                    data = content.readNBytes(bufferSize);
                    if (data.length > 0) {
                        callback.accept(data);
                    }
                } while (data.length > 0);

                return new HttpReply(statusCode, "", response.getAllHeaders());
            } else {
                data = content.readAllBytes();
                String body = new String(data, StandardCharsets.UTF_8);
                return new HttpReply(statusCode, body, response.getAllHeaders());
            }
        } catch (Exception e) {
            logger.warn("Failed connecting", e);
            return null;
        }
    }

    public HttpReply authDownloadPost(Session session, String url, Map<String, Object> params, int bufferSize, Consumer<byte[]> callback, Integer timeout) {
        try {
            CloseableHttpResponse response = httpClientExecute(session, url, params, timeout);

            int statusCode = response.getStatusLine().getStatusCode();
            InputStream content = response.getEntity().getContent();
            byte[] data;
            if (statusCode == 200) {
                do {
                    data = content.readNBytes(bufferSize);
                    if (data.length > 0) {
                        callback.accept(data);
                    }
                } while (data.length > 0);

                return new HttpReply(statusCode, "", response.getAllHeaders());
            } else {
                data = content.readAllBytes();
                String body = new String(data, StandardCharsets.UTF_8);
                return new HttpReply(statusCode, body, response.getAllHeaders());
            }
        } catch (Exception e) {
            logger.warn("Failed connecting", e);
            return null;
        }
    }

    public HttpReply syncPost(String url, Map<String, Object> params) {
        try {
            CloseableHttpClient httpClient = getHttpClient();
            HttpPost request = new HttpPost(url);

            request.addHeader(HTTP.CONTENT_ENCODING, "gzip");
            request.addHeader(HTTP.CONTENT_TYPE, "application/json");
            request.setEntity(new StringEntity(Utils.getGson().toJson(params)));

            int nTry = 0;
            while (nTry < RETRIES) {
                try {
                    CloseableHttpResponse response = httpClient.execute(request);
                    int statusCode = response.getStatusLine().getStatusCode();
                    byte[] data = response.getEntity().getContent().readAllBytes();
                    String body = new String(data, StandardCharsets.UTF_8);
                    return new HttpReply(statusCode, body, response.getAllHeaders());
                } catch (Exception e) {
                    try {
                        Thread.sleep((int) (THROTTLE_MS + (nTry > 10 ? Math.sqrt(nTry) * 500 : 0)));
                    } catch (InterruptedException ex) {
                    }
                    if (e instanceof HttpHostConnectException) {
                        logger.warn("Waiting for connection...");
                    } else {
                        logger.warn("Failed connecting", e);
                    }
                    nTry++;
                }
            }
            logger.error("Failed connecting, giving up");
            return null;
        } catch (IOException e) {
            logger.error("Failed API call", e);
            return null;
        }
    }

    public HttpReply authPost(Session session, String url, Map<String, Object> params, Integer timeout) {
        try {
            CloseableHttpResponse response = httpClientExecute(session, url, params, timeout);

            int statusCode = response.getStatusLine().getStatusCode();
            byte[] data = response.getEntity().getContent().readAllBytes();
            String body = new String(data, StandardCharsets.UTF_8);

            return new HttpReply(statusCode, body, response.getAllHeaders());

        } catch (IOException e) {
            logger.error("Failed API call", e);
            return null;
        }
    }

    private CloseableHttpResponse httpClientExecute(Session session, String url, Map<String, Object> params, Integer timeout) throws IOException {
        CloseableHttpClient httpClient = getHttpClient();

        RequestConfig.Builder requestConfig = RequestConfig.custom();
        int connectionTimeout = (timeout != null ? Math.max(timeout, CONNECTION_TIMEOUT) : CONNECTION_TIMEOUT) * 1000;
        requestConfig.setConnectTimeout(connectionTimeout);
        requestConfig.setConnectionRequestTimeout(connectionTimeout);
        requestConfig.setSocketTimeout(connectionTimeout);

        HttpPost request = new HttpPost(url);
        request.setConfig(requestConfig.build());

        String reqBody = Utils.getGson().toJson(params);

        String nonce = Long.toString(session.getNonce().incrementAndGet());
        request.addHeader(HTTP.CONTENT_ENCODING, "gzip");
        request.addHeader(HTTP.CONTENT_TYPE, "application/json");
        request.addHeader("x-api-key", session.getApiKey());
        request.addHeader("x-nonce", nonce);
        String toSign = url.substring(url.lastIndexOf("/", url.lastIndexOf("/") - 1))
                + "\n" + session.getApiKey()
                + "\n" + nonce
                + "\n" + (reqBody.isEmpty() ? "{}" : reqBody);
        String signature = Hash.signRequestB64(session.getSecret(), toSign);
        request.addHeader("x-sig", signature);
        request.setEntity(new StringEntity(reqBody));

        return httpClient.execute(request);
    }
}
