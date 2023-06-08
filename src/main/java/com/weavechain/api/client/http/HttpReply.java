package com.weavechain.api.client.http;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.http.Header;

@Getter
@AllArgsConstructor
public class HttpReply {

    private final int statusCode;

    private final String body;

    private Header[] replyHeaders;
}
