package com.weavechain.api.client.zmq;

import com.weavechain.api.ApiContext;
import com.weavechain.api.client.async.AsyncRequestsClient;
import com.weavechain.api.client.async.PendingRequest;
import com.weavechain.api.config.transport.ZeroMQClientConfig;
import com.weavechain.core.batching.BatchHelper;
import com.weavechain.core.encoding.ContentEncoder;
import com.weavechain.core.encoding.Encoding;
import com.weavechain.core.encoding.Utils;
import com.weavechain.core.error.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

public class ZeroMQApiClient extends AsyncRequestsClient {

    static final Logger logger = LoggerFactory.getLogger(ZeroMQApiClient.class);

    private final ZeroMQClientConfig config;

    private ZContext context;

    private ZMQ.Socket client;

    private final BatchHelper batchHelper = new BatchHelper();

    private final ContentEncoder contentEncoder = Encoding.getDefaultContentEncoder();

    public ZeroMQApiClient(ZeroMQClientConfig config, ApiContext apiContext) {
        super(apiContext);
        this.config = config.copy();
    }

    @Override
    public boolean init() {
        try {
            client = connect();

            keysInit();

            return true;
        } catch (Exception e) {
            logger.error("Could not retrieve server public key", e);
            return false;
        }
    }

    private ZMQ.Socket connect() {
        context = new ZContext();

        ZMQ.Socket socket = context.createSocket(SocketType.REQ);
        String host = Utils.parseHost(config.getHost());
        String url = config.isIPC()
                ? "ipc://" + host
                : ("tcp://"
                + (host != null ? host : "localhost")
                + ":" + config.getPort());
        if (!socket.connect(url)) {
            logger.error("Connection failed");
        }
        return socket;
    }

    protected void addPendingRequest(PendingRequest pending, String requestID) {
        //do nothing
    }

    @SuppressWarnings("unchecked")
    protected void sendRequest(String id, PendingRequest req, boolean isAuthenticated) {
        if (req.getMessage() != null) {
            if (!client.send(req.getMessage().getBytes(ZMQ.CHARSET), 0)) {
                logger.error("Failed sending message");
            }

            byte[] reply = client.recv(0);
            String message = new String(reply, ZMQ.CHARSET);
            Map<String, Object> msg = Utils.getGson().fromJson(message, Map.class);

            OperationResult result = OperationResultSerializer.from(msg.get("reply"));

            String error = (String)msg.get("error");
            if (error != null) {
                logger.error("Error: " + error);
            }

            req.getResult().complete(result);
        }
    }
}
