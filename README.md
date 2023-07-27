# twilight-cloudflare-workers

Verify Discord interactions on Cloudflare Workers with Twilight. Supports
[`worker`] 0.0.17 and [Twilight] 0.15 on the next branch.

### API

The primary function in the API is `process`. It takes a Worker request and
your application's public key for Discord, verifies the request signature to
ensure it's from Discord, and deserializes the  request body as an interaction.
Using it looks like this:

```rust
let key = "discord public key from environment";

let interaction = match twilight_cf_worker::process(&mut request, key) {
    Ok(interaction) => interaction,
    Err(source) => {
        // Return the error as a Worker response.
        return source.response();
    }
};

// work with the interaction..
```

The other function in the API is `response`, which takes an interaction response
and produces a Worker response:

```rust
return twilight_cf_worker::response(interaction_response);
```

### License

ISC.

[Twilight]: https://twilight.rs
[`worker`]: https://crates.io/crates/worker
