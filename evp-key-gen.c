
void RSA_gen() {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    // or ctx from param (wchich is set before)
    // ctx = EVP_PKEY_CTX_new(param);
    if (!ctx)
        /* Error occurred */
    if (EVP_PKEY_keygen_init(ctx) <= 0)
        /* Error */
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        /* Error */

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        /* Error */
}

void DH_gen() {
    /* Use built-in parameters */
    if(NULL == (params = EVP_PKEY_new())) handleErrors();
    if(1 != EVP_PKEY_set1_DH(params,DH_get_2048_256())) handleErrors();

    /* Create context for the key generation */
    if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();

    /* Generate a new key */
    if(1 != EVP_PKEY_keygen_init(kctx)) handleErrors();
    if(1 != EVP_PKEY_keygen(kctx, &dhkey)) handleErrors();
};


void DH_key_exchange() {
    //1. create DH public params (generator: 2 or 5, numbits)

    //2. each user uses public params to create their own key_pair (pub+prv)
    // e.g. dhkey1 for user1 and dhkey2 for user2

    //3. the users must exchange their public keys (user1_pub,user2_pub)

    //4. after exchanging public keys users can derive shared secret keya (symetric)
    //shared_key = dh_derive(user1_pub, user2_prv); //shared key derived by user1
    //shared_key = dh_derive(user2_pub, user1_prv); //shared key derived by user2

    shared_len = DH_compute_key(shared_key, pubkey, privkey)
}
