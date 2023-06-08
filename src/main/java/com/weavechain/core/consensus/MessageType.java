package com.weavechain.core.consensus;

public enum MessageType {

    none,

    vote,

    request,

    reply,

    preprepare,

    prepare,

    commit,

    seal,

    sealed,

    newview,

    viewchange

}