// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;
use crate::builtins::traits::{Builtin, BuiltinFunc};
use anyhow::{Result, bail};

#[cfg(feature = "time")]
use chrono::TimeZone;
use serde::{de::DeserializeOwned, Serialize};

/// Context passed through builtin evaluation
pub trait EvaluationContext: Send + 'static {
    /// The type of random number generator used by this context
    #[cfg(feature = "rng")]
    type Rng: rand::Rng;

    /// Get a [`rand::Rng`]
    #[cfg(feature = "rng")]
    fn get_rng(&mut self) -> Self::Rng;

    /// Get the current date and time
    #[cfg(feature = "time")]
    fn now(&self) -> chrono::DateTime<chrono::Utc>;

    /// Notify the context on evaluation start, so it can clean itself up
    fn evaluation_start(&mut self);

    /// Get a value from the evaluation cache
    ///
    /// # Errors
    ///
    /// If the key failed to serialize, or the value failed to deserialize
    fn cache_get<K: Serialize, C: DeserializeOwned>(&mut self, key: &K) -> Result<Option<C>>;

    /// Push a value to the evaluation cache
    ///
    /// # Errors
    ///
    /// If the key or the value failed to serialize
    fn cache_set<K: Serialize, C: Serialize>(&mut self, key: &K, content: &C) -> Result<()>;

    /// Resolve a builtin based on its name
    ///
    /// # Errors
    ///
    /// Returns an error if the builtin is not known
    fn resolve_builtin<C: EvaluationContext>(&self, name: &str) -> Result<Box<dyn Builtin<C>>>;
}

/// The default evaluation context implementation
pub struct DefaultContext {
    cache: HashMap<String, serde_json::Value>,

    #[cfg(feature = "time")]
    evaluation_time: chrono::DateTime<chrono::Utc>,
}

#[allow(clippy::derivable_impls)]
impl Default for DefaultContext {
    fn default() -> Self {
        Self {
            cache: HashMap::new(),

            #[cfg(feature = "time")]
            evaluation_time: chrono::Utc.timestamp_nanos(0),
        }
    }
}

impl EvaluationContext for DefaultContext {
    #[cfg(feature = "rng")]
    type Rng = rand::rngs::ThreadRng;

    #[cfg(feature = "rng")]
    fn get_rng(&mut self) -> Self::Rng {
        rand::thread_rng()
    }

    #[cfg(feature = "time")]
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.evaluation_time
    }

    fn evaluation_start(&mut self) {
        // Clear the cache
        self.cache = HashMap::new();

        #[cfg(feature = "time")]
        {
            // Set the evaluation time to now
            self.evaluation_time = chrono::Utc::now();
        }
    }

    fn cache_get<K: Serialize, C: DeserializeOwned>(&mut self, key: &K) -> Result<Option<C>> {
        let key = serde_json::to_string(&key)?;
        let Some(value) = self.cache.get(&key) else {
            return Ok(None);
        };

        let value = serde_json::from_value(value.clone())?;
        Ok(value)
    }

    fn cache_set<K: Serialize, C: Serialize>(&mut self, key: &K, content: &C) -> Result<()> {
        let key = serde_json::to_string(key)?;
        let content = serde_json::to_value(content)?;
        self.cache.insert(key, content);
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn resolve_builtin<C: EvaluationContext>(&self, name: &str) -> Result<Box<dyn Builtin<C>>> {
        match name {
            #[cfg(feature = "base64url-builtins")]
            "base64url.encode_no_pad" => Ok(crate::builtins::impls::base64url::encode_no_pad.wrap()),

            #[cfg(all(feature = "crypto-md5-builtins", feature = "crypto-hmac-builtins"))]
            "crypto.hmac.md5" => Ok(crate::builtins::impls::crypto::hmac::md5.wrap()),

            #[cfg(all(feature = "crypto-sha1-builtins", feature = "crypto-hmac-builtins"))]
            "crypto.hmac.sha1" => Ok(crate::builtins::impls::crypto::hmac::sha1.wrap()),

            #[cfg(all(feature = "crypto-sha2-builtins", feature = "crypto-hmac-builtins"))]
            "crypto.hmac.sha256" => Ok(crate::builtins::impls::crypto::hmac::sha256.wrap()),

            #[cfg(all(feature = "crypto-sha2-builtins", feature = "crypto-hmac-builtins"))]
            "crypto.hmac.sha512" => Ok(crate::builtins::impls::crypto::hmac::sha512.wrap()),

            #[cfg(all(feature = "crypto-md5-builtins", feature = "crypto-digest-builtins"))]
            "crypto.md5" => Ok(crate::builtins::impls::crypto::digest::md5.wrap()),

            #[cfg(all(feature = "crypto-sha1-builtins", feature = "crypto-digest-builtins"))]
            "crypto.sha1" => Ok(crate::builtins::impls::crypto::digest::sha1.wrap()),

            #[cfg(all(feature = "crypto-sha2-builtins", feature = "crypto-digest-builtins"))]
            "crypto.sha256" => Ok(crate::builtins::impls::crypto::digest::sha256.wrap()),

            "crypto.x509.parse_and_verify_certificates" => {
                Ok(crate::builtins::impls::crypto::x509::parse_and_verify_certificates.wrap())
            }
            "crypto.x509.parse_certificate_request" => {
                Ok(crate::builtins::impls::crypto::x509::parse_certificate_request.wrap())
            }
            "crypto.x509.parse_certificates" => {
                Ok(crate::builtins::impls::crypto::x509::parse_certificates.wrap())
            }
            "crypto.x509.parse_rsa_private_key" => {
                Ok(crate::builtins::impls::crypto::x509::parse_rsa_private_key.wrap())
            }
            "glob.quote_meta" => Ok(crate::builtins::impls::glob::quote_meta.wrap()),
            "graph.reachable_paths" => Ok(crate::builtins::impls::graph::reachable_paths.wrap()),
            "graphql.is_valid" => Ok(crate::builtins::impls::graphql::is_valid.wrap()),
            "graphql.parse" => Ok(crate::builtins::impls::graphql::parse.wrap()),
            "graphql.parse_and_verify" => Ok(crate::builtins::impls::graphql::parse_and_verify.wrap()),
            "graphql.parse_query" => Ok(crate::builtins::impls::graphql::parse_query.wrap()),
            "graphql.parse_schema" => Ok(crate::builtins::impls::graphql::parse_schema.wrap()),

            #[cfg(feature = "hex-builtins")]
            "hex.decode" => Ok(crate::builtins::impls::hex::decode.wrap()),

            #[cfg(feature = "hex-builtins")]
            "hex.encode" => Ok(crate::builtins::impls::hex::encode.wrap()),

            "http.send" => Ok(crate::builtins::impls::http::send.wrap()),
            "indexof_n" => Ok(crate::builtins::impls::indexof_n.wrap()),
            "io.jwt.decode" => Ok(crate::builtins::impls::io::jwt::decode.wrap()),
            "io.jwt.decode_verify" => Ok(crate::builtins::impls::io::jwt::decode_verify.wrap()),
            "io.jwt.encode_sign" => Ok(crate::builtins::impls::io::jwt::encode_sign.wrap()),
            "io.jwt.encode_sign_raw" => Ok(crate::builtins::impls::io::jwt::encode_sign_raw.wrap()),
            "io.jwt.verify_es256" => Ok(crate::builtins::impls::io::jwt::verify_es256.wrap()),
            "io.jwt.verify_es384" => Ok(crate::builtins::impls::io::jwt::verify_es384.wrap()),
            "io.jwt.verify_es512" => Ok(crate::builtins::impls::io::jwt::verify_es512.wrap()),
            "io.jwt.verify_hs256" => Ok(crate::builtins::impls::io::jwt::verify_hs256.wrap()),
            "io.jwt.verify_hs384" => Ok(crate::builtins::impls::io::jwt::verify_hs384.wrap()),
            "io.jwt.verify_hs512" => Ok(crate::builtins::impls::io::jwt::verify_hs512.wrap()),
            "io.jwt.verify_ps256" => Ok(crate::builtins::impls::io::jwt::verify_ps256.wrap()),
            "io.jwt.verify_ps384" => Ok(crate::builtins::impls::io::jwt::verify_ps384.wrap()),
            "io.jwt.verify_ps512" => Ok(crate::builtins::impls::io::jwt::verify_ps512.wrap()),
            "io.jwt.verify_rs256" => Ok(crate::builtins::impls::io::jwt::verify_rs256.wrap()),
            "io.jwt.verify_rs384" => Ok(crate::builtins::impls::io::jwt::verify_rs384.wrap()),
            "io.jwt.verify_rs512" => Ok(crate::builtins::impls::io::jwt::verify_rs512.wrap()),

            #[cfg(feature = "json-builtins")]
            "json.patch" => Ok(crate::builtins::impls::json::patch.wrap()),

            "net.cidr_contains_matches" => Ok(crate::builtins::impls::net::cidr_contains_matches.wrap()),
            "net.cidr_expand" => Ok(crate::builtins::impls::net::cidr_expand.wrap()),
            "net.cidr_merge" => Ok(crate::builtins::impls::net::cidr_merge.wrap()),
            "net.lookup_ip_addr" => Ok(crate::builtins::impls::net::lookup_ip_addr.wrap()),
            "object.union_n" => Ok(crate::builtins::impls::object::union_n.wrap()),
            "opa.runtime" => Ok(crate::builtins::impls::opa::runtime.wrap()),

            #[cfg(feature = "rng")]
            "rand.intn" => Ok(crate::builtins::impls::rand::intn.wrap()),

            "regex.find_n" => Ok(crate::builtins::impls::regex::find_n.wrap()),
            "regex.globs_match" => Ok(crate::builtins::impls::regex::globs_match.wrap()),
            "regex.split" => Ok(crate::builtins::impls::regex::split.wrap()),
            "regex.template_match" => Ok(crate::builtins::impls::regex::template_match.wrap()),
            "rego.parse_module" => Ok(crate::builtins::impls::rego::parse_module.wrap()),

            #[cfg(feature = "semver-builtins")]
            "semver.compare" => Ok(crate::builtins::impls::semver::compare.wrap()),

            #[cfg(feature = "semver-builtins")]
            "semver.is_valid" => Ok(crate::builtins::impls::semver::is_valid.wrap()),

            #[cfg(feature = "sprintf-builtins")]
            "sprintf" => Ok(crate::builtins::impls::sprintf.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.add_date" => Ok(crate::builtins::impls::time::add_date.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.clock" => Ok(crate::builtins::impls::time::clock.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.date" => Ok(crate::builtins::impls::time::date.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.diff" => Ok(crate::builtins::impls::time::diff.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.now_ns" => Ok(crate::builtins::impls::time::now_ns.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.parse_duration_ns" => Ok(crate::builtins::impls::time::parse_duration_ns.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.parse_ns" => Ok(crate::builtins::impls::time::parse_ns.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.parse_rfc3339_ns" => Ok(crate::builtins::impls::time::parse_rfc3339_ns.wrap()),

            #[cfg(feature = "time-builtins")]
            "time.weekday" => Ok(crate::builtins::impls::time::weekday.wrap()),

            "trace" => Ok(crate::builtins::impls::trace.wrap()),

            #[cfg(feature = "units-builtins")]
            "units.parse" => Ok(crate::builtins::impls::units::parse.wrap()),

            #[cfg(feature = "units-builtins")]
            "units.parse_bytes" => Ok(crate::builtins::impls::units::parse_bytes.wrap()),

            #[cfg(feature = "urlquery-builtins")]
            "urlquery.decode" => Ok(crate::builtins::impls::urlquery::decode.wrap()),

            #[cfg(feature = "urlquery-builtins")]
            "urlquery.decode_object" => Ok(crate::builtins::impls::urlquery::decode_object.wrap()),

            #[cfg(feature = "urlquery-builtins")]
            "urlquery.encode" => Ok(crate::builtins::impls::urlquery::encode.wrap()),

            #[cfg(feature = "urlquery-builtins")]
            "urlquery.encode_object" => Ok(crate::builtins::impls::urlquery::encode_object.wrap()),

            "uuid.rfc4122" => Ok(crate::builtins::impls::uuid::rfc4122.wrap()),

            #[cfg(feature = "yaml-builtins")]
            "yaml.is_valid" => Ok(crate::builtins::impls::yaml::is_valid.wrap()),

            #[cfg(feature = "yaml-builtins")]
            "yaml.marshal" => Ok(crate::builtins::impls::yaml::marshal.wrap()),

            #[cfg(feature = "yaml-builtins")]
            "yaml.unmarshal" => Ok(crate::builtins::impls::yaml::unmarshal.wrap()),
            _ => bail!("unknown builtin"),
        }
    }
}

pub mod tests {
    use anyhow::Result;
    #[cfg(feature = "time")]
    use chrono::TimeZone;
    use serde::{de::DeserializeOwned, Serialize};

    use crate::{DefaultContext, EvaluationContext};

    /// A context used in tests
    pub struct TestContext {
        inner: DefaultContext,

        #[cfg(feature = "time")]
        clock: chrono::DateTime<chrono::Utc>,

        #[cfg(feature = "rng")]
        seed: u64,
    }

    #[allow(clippy::derivable_impls)]
    impl Default for TestContext {
        fn default() -> Self {
            Self {
                inner: DefaultContext::default(),

                #[cfg(feature = "time")]
                clock: chrono::Utc
                    // Corresponds to 2020-07-14T12:53:22Z
                    // We're using this method because it's available on old versions of chrono
                    .timestamp_opt(1_594_731_202, 0)
                    .unwrap(),

                #[cfg(feature = "rng")]
                seed: 0,
            }
        }
    }

    impl EvaluationContext for TestContext {
        #[cfg(feature = "rng")]
        type Rng = rand::rngs::StdRng;

        fn evaluation_start(&mut self) {
            self.inner.evaluation_start();
        }

        #[cfg(feature = "time")]
        fn now(&self) -> chrono::DateTime<chrono::Utc> {
            self.clock
        }

        #[cfg(feature = "rng")]
        fn get_rng(&mut self) -> Self::Rng {
            use rand::SeedableRng;

            rand::rngs::StdRng::seed_from_u64(self.seed)
        }

        fn cache_get<K: Serialize, C: DeserializeOwned>(&mut self, key: &K) -> Result<Option<C>> {
            self.inner.cache_get(key)
        }

        fn cache_set<K: Serialize, C: Serialize>(&mut self, key: &K, content: &C) -> Result<()> {
            self.inner.cache_set(key, content)
        }

        fn resolve_builtin<C: EvaluationContext>(&self, name: &str) -> Result<Box<dyn crate::builtins::traits::Builtin<C>>> {
            self.inner.resolve_builtin(name)
        }
    }
}
