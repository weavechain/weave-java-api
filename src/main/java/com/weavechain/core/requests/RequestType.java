package com.weavechain.core.requests;

public enum RequestType {

    ping,
    version,
    public_key,
    sig_key,
    bls_key,
    rsa_key,

    file,

    fwd_api,
    forward_api,

    plugin_call,

    upload,
    upload_api,

    login,
    proxy_login,
    logout,
    terms,

    enc,

    status,
    peer_status,

    create,
    drop,
    read,
    count,
    delete,
    download_table,
    write,
    sign,
    subscribe,
    unsubscribe,
    download_dataset,
    publish_dataset,
    enable_product,
    run_task,
    publish_task,

    proxy_encrypt,
    proxy_reencrypt,

    blind_signature,

    storage_proof,
    zk_storage_proof,
    hashes,
    merkle_tree,
    merkle_proof,
    verify_merkle_hash,
    zk_merkle_tree,
    root_hash,
    mimc_hash,
    update_proofs,
    proofs_last_hash,

    compute,
    he_get_inputs,
    he_get_outputs,
    he_encode,
    mpc,
    mpc_init,
    mpc_proto,
    f_learn,

    zk_proof,
    zk_data_proof,
    verify_zk_proof,

    task_lineage,
    hash_checkpoint,
    verify_task_lineage,
    task_output_data,


    post_message,
    poll_messages,

    deploy_oracle,
    deploy_feed,
    remove_feed,
    start_feed,
    stop_feed,

    broadcast,

    insert,
    query,

    register_peer,
    unregister_peer,
    peers,
    blocks,
    advance,

    create_account,
    deploy,
    call,
    balance,
    transfer,
    update_fees,
    contract_state,
    broadcast_block,
    broadcast_chain,

    issue_credentials,
    verify_credentials,
    create_presentation,
    sign_presentation,
    verify_presentation,

    verify_data_signature,

    forwarded_request,
    get_sidechain_details,
    get_user_details,
    get_nodes,
    get_scopes,
    get_tables,
    get_table_definition,
    get_node_config,
    get_account_notifications,
    update_layout,
    update_config,
    reset_config,
    withdraw,
    withdraw_auth,
    create_user_account,
    grant_role,

    threshold_sig_pubkey_round_1,
    threshold_sig_round_2,
    read_threshold_sig_pub_key,
    set_threshold_sig_pub_key,

    history,
    writers,
    tasks,
    split_learn,
    lineage,
    get_image
}