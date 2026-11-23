# @summary Soundwave's PE user and role, owned by the primary.
#
# Declare this on the PE primary, where the RBAC types can reach the console
# with the primary's own certificate. It makes a role that can register a
# transformer and push to Vulnerability Remediation and nothing else, and a
# user holding only that role. Give soundwave's own node the same password as
# `soundwave::token_password` and it mints and renews its own short-lived
# token, so no token is ever in a catalogue.
#
# The RBAC types come from conductor-rbac (albatrossflavour's fork, whose
# rbac_token renews), which is not a metadata dependency: add it to the
# Puppetfile as `rbac` before declaring this class.
#
# @param password
#   The user's password. A Sensitive class parameter is still written into the
#   catalogue in plaintext, since class parameters are recorded there, so pass
#   the Deferred that `node_encrypt::secret()` returns and the catalogue carries
#   only ciphertext the primary can open.
# @param login
#   The user's login.
# @param role
#   The role's display name.
# @param email
#   The user's email. The RBAC API insists on one.
# @param display_name
#   The user's display name.
# @param check_password
#   Log in as the user each run and reset the password if it has drifted.
#
# @example On the primary, with the password from node_encrypt
#   class { 'soundwave::rbac_user':
#     password => node_encrypt::secret(lookup('soundwave::rbac_password')),
#   }
#
class soundwave::rbac_user (
  Variant[Sensitive[String[1]], Deferred] $password,
  String[1] $login = 'soundwave',
  String[1] $role = 'Soundwave',
  String[1] $email = "soundwave@${facts['networking']['domain']}",
  String[1] $display_name = 'Soundwave',
  Boolean $check_password = true,
) {
  unless defined('rbac_user') and defined('rbac_role') {
    fail('soundwave::rbac_user needs the rbac_user and rbac_role types from conductor-rbac (git@github.com:albatrossflavour/conductor-rbac.git), so add it to the Puppetfile as rbac')
  }

  rbac_role { $role:
    ensure      => present,
    description => 'Soundwave vulnerability transformer: registers its transformer and pushes results to Vulnerability Remediation, nothing else',
    permissions => [
      { 'object_type' => 'premium_patching_vulnerability_management_transformers', 'action' => 'create', 'instance' => '*' },
      { 'object_type' => 'premium_patching_vulnerability_management_vulnerabilities', 'action' => 'create', 'instance' => '*' },
    ],
  }

  rbac_user { $login:
    ensure         => present,
    display_name   => $display_name,
    email          => $email,
    password       => $password,
    roles          => [$role],
    check_password => $check_password,
    require        => Rbac_role[$role],
  }
}
