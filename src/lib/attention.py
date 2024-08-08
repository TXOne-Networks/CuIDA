import os, time, pickle
import numpy as np
BLOCK_SIZE = 20

 # [n_q, d_k], [n_k, d_k], [n_k, d_v], [n_q, n_k] -> [n_q, d_v]
def attention(q, k, v, mask): 
    def softmax(x):
        exp_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
        return exp_x / np.sum(exp_x, axis=-1, keepdims=True)
    return softmax(q @ k.T / np.sqrt(q.shape[-1]) + mask) @ v

def net_forward(x): 
    T = x.shape
    x =  pe_emb[: BLOCK_SIZE] + emb[x]

    # causal mask to hide future inputs from being attended to
    causal_mask = (1 - np.tri(x.shape[0], dtype=x.dtype)) * -1e10  # [n_seq, n_seq]
    att_x = attention( x @ npwQKV[0].T, x @ npwQKV[1].T, x @ npwQKV[2].T, causal_mask )

    def ReLU(x):
        return x * (x > 0)
    def linear(x, w, b):  # [m, in], [in, out], [out] -> [m, out]
        return x @ w + b
    def layer_norm(x, g, b, eps: float = 1e-5):
        mean = np.mean(x, axis=-1, keepdims=True)
        variance = np.var(x, axis=-1, keepdims=True)
        x = (x - mean) / np.sqrt(variance + eps)  # normalize x to have mean=0 and var=1 over last axis
        return g * x + b  # scale and offset with gamma/beta params

    x = linear(att_x, *att_seq_ln1 ) 
    x = ReLU( x ) 
    x = linear( x, *att_seq_ln2 ) 
    x = layer_norm( x, *att_seq_laynorm )

    x = x.reshape( 1, BLOCK_SIZE*n_embd )
    v = linear( x, *lm_head )
    return v

def loadModel_lastCheckpoint(pathToModel:str):
    global verifyFor64, stoi, itos, net, vocab_size, n_embd, \
        npwQKV, att_seq_ln1, att_seq_ln2, att_seq_laynorm, emb, pe_emb, lm_head

    verifyFor64 = False
    stoi, itos, vocab_size, n_embd, \
        npwQKV, att_seq_ln1, att_seq_ln2, att_seq_laynorm, \
        emb, pe_emb, lm_head = pickle.load(open( pathToModel, "rb" ))

def pretty_symbolic(token):
    if isinstance(token, tuple):
        if token[0] == "apicall":
            _, callstr, argsym = token
            token = f"RET_OF_FUNC{len(argsym)}"
        else:
            raise

    elif isinstance(token, str):
        if "." in token:
            token = token.split(".")[1]
        elif "0x" in token:
            probval = int(token, base=16)
            if 0xfffffff00000000 & probval: # this value too large for windows, believe that's vivisect shit.
                 token = "VIV_LARGE_CACHE"
            else:
                token = token
        #elif not any(x in token for x in ["FUNC_RET", "DLL_IMG_PTR", "LOCAL_BUFF", "MEM_BUFF", "STR_UNICODE_", "STR_ANSI_"]):
        #    raise
    else:
        raise
    return token

def update_vocab(token, is_trainning = True):
    token = pretty_symbolic(token)
    if not token in stoi:
        if is_trainning:
            stoi[token] = len(itos) 
            itos[len(itos)] = token
        else: # inference mode, should not update new tokens!
            token = "MEM_BUFF"
    return stoi[token]

import numpy as np
def predictApiList( argv ) -> str:
    curr = np.array( [ 0 ] * BLOCK_SIZE )
    for i, token in enumerate(argv):
        curr[i] = update_vocab(token, is_trainning= False)

    prediction = net_forward(curr)
    
    guessList = np.argpartition(prediction[0], -5)[-5:] # Top-k = 5
    guess_winapi = [ itos.get( x ) for x in guessList]
    return guess_winapi
