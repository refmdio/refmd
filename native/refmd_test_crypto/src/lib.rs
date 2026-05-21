use ml_dsa::{ExpandedSigningKey, ExpandedSigningKeyBytes, KeyGen, MlDsa65, Seed};

#[rustler::nif(schedule = "DirtyCpu")]
fn keypair_from_seed<'a>(
    env: rustler::Env<'a>,
    seed: rustler::Binary,
) -> Result<(rustler::Binary<'a>, rustler::Binary<'a>), rustler::Error> {
    let seed = seed.as_slice().to_vec();
    let (private_key, public_key) = run_task(move || -> Option<(Vec<u8>, Vec<u8>)> {
        let seed: Seed = seed.as_slice().try_into().ok()?;
        let signing_key = MlDsa65::from_seed(&seed);

        #[allow(deprecated)]
        let private_key = signing_key.signing_key().to_expanded();
        let public_key = signing_key.signing_key().verifying_key().encode();

        Some((private_key.as_slice().to_vec(), public_key.as_slice().to_vec()))
    })?
    .ok_or(rustler::Error::BadArg)?;

    Ok((
        binary_from_slice(env, private_key.as_slice()),
        binary_from_slice(env, public_key.as_slice()),
    ))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign<'a>(
    env: rustler::Env<'a>,
    message: rustler::Binary,
    context: rustler::Binary,
    private_key: rustler::Binary,
) -> Result<rustler::Binary<'a>, rustler::Error> {
    if context.as_slice().len() > 255 {
        return Err(rustler::Error::BadArg);
    }

    let message = message.as_slice().to_vec();
    let context = context.as_slice().to_vec();
    let private_key = private_key.as_slice().to_vec();
    let signature = run_task(move || -> Option<Vec<u8>> {
        let private_key: ExpandedSigningKeyBytes<MlDsa65> =
            private_key.as_slice().try_into().ok()?;

        #[allow(deprecated)]
        let signing_key = ExpandedSigningKey::<MlDsa65>::from_expanded(&private_key);
        let signature = signing_key
            .sign_deterministic(message.as_slice(), context.as_slice())
            .ok()?
            .encode();

        Some(signature.as_slice().to_vec())
    })?
    .ok_or(rustler::Error::BadArg)?;

    Ok(binary_from_slice(env, signature.as_slice()))
}

fn binary_from_slice<'a>(env: rustler::Env<'a>, bytes: &[u8]) -> rustler::Binary<'a> {
    let mut out = rustler::OwnedBinary::new(bytes.len()).unwrap();
    out.as_mut_slice().copy_from_slice(bytes);
    out.release(env)
}

fn run_task<T, F>(task: F) -> Result<T, rustler::Error>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    Ok(std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(task)
        .map_err(|_| rustler::Error::BadArg)?
        .join()
        .map_err(|_| rustler::Error::BadArg)?)
}

rustler::init!("Elixir.RefMD.TestCrypto.Native");
