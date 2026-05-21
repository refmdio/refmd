use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

#[rustler::nif(schedule = "DirtyCpu")]
fn hash<'a>(env: rustler::Env<'a>, data: rustler::Binary) -> rustler::Binary<'a> {
    let hash = blake3::hash(data.as_slice());
    let mut out = rustler::OwnedBinary::new(32).unwrap();
    out.as_mut_slice().copy_from_slice(hash.as_bytes());
    out.release(env)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn mldsa65_verify(
    message: rustler::Binary,
    context: rustler::Binary,
    signature: rustler::Binary,
    public_key: rustler::Binary,
) -> bool {
    if context.as_slice().len() > 255 {
        return false;
    }

    let public_key: EncodedVerifyingKey<MlDsa65> =
        match <&[u8] as TryInto<EncodedVerifyingKey<MlDsa65>>>::try_into(public_key.as_slice()) {
            Ok(public_key) => public_key,
            Err(_) => return false,
        };
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&public_key);

    let signature: EncodedSignature<MlDsa65> =
        match <&[u8] as TryInto<EncodedSignature<MlDsa65>>>::try_into(signature.as_slice()) {
            Ok(signature) => signature,
            Err(_) => return false,
        };
    let Some(signature) = Signature::<MlDsa65>::decode(&signature) else {
        return false;
    };

    verifying_key.verify_with_context(message.as_slice(), context.as_slice(), &signature)
}

rustler::init!("Elixir.RefMD.Crypto.Native");
