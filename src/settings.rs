use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kubewarden_policy_sdk::settings::Validatable;

    use super::*;

    #[test]
    fn accept_settings() {
        let settings = Settings {};

        assert!(settings.validate().is_ok());
    }
}
