# @summary Soundwave, the vulnerability transformer, and its cassettes.
#
# Soundwave pushes one merged set of findings into Puppet Enterprise's
# Vulnerability Remediation service. It never parses a scanner. Each cassette
# writes the scanner-neutral findings file (docs/findings-file.md) into
# $cassette_dir and Soundwave merges whatever is there, so a third scanner is
# another cassette rather than another integration.
#
# Two cassettes ship with it, each named for its scanner. The **openvas**
# cassette reads Greenbone over GMP, and is on by default. The **vuls** cassette
# reads the run the vuls module last recorded as complete, and is off by
# default. Each runs before the push, and one that fails leaves its previous
# file in place, so the push still goes and the cassette's staleness alert says
# how old that file is. Neither is given a platform to own: they may report the
# same host, package and CVE, and sorting out what overlaps is Soundwave's job
# rather than a convention either of them keeps.
#
# This was openvas_transformer until 2026-09-16. It keeps the same transformer
# ID, fqdn_uuid of the node's certname, so VR's history carries on unbroken.
#
# @param pe_token
#   PE authentication token with permission to push to the VRS service.
# @param pe_host
#   PE primary to push to. Defaults to the Puppet server that compiled this
#   catalogue, so it only needs setting when that isn't the PE primary, or when
#   there is no server at all (`puppet apply`).
# @param gmp_password
#   Password for the GMP user used to read reports. Defaults to
#   `openvas::scan_observer_password`, so the read-only user the openvas module
#   creates is set once. Required when openvas_cassette is on, unused otherwise.
# @param gmp_username
#   GMP user used to read reports. Defaults to `openvas::scan_observer_user`,
#   and to admin when that isn't set.
# @param compose_file
#   Absolute path to the Greenbone docker compose file on this host.
# @param gmp_service
#   Compose service that provides gvm-cli with the gvmd socket mounted.
# @param gmp_socket_path
#   Path to the gvmd socket inside the gvm-tools container.
# @param scan_name
#   Optional task name to restrict which report is pulled. Empty means every task's latest.
# @param docker_cmd
#   Docker executable used to reach the compose stack.
# @param gmp_timeout
#   Seconds to wait for a GMP command before giving up.
# @param manage_python
#   Whether this module installs and manages Python.
# @param run_in_venv
#   Run the transformer inside a Python virtual environment.
# @param python_version
#   Pin a specific Python version instead of the OS default.
# @param sync_schedule
#   Systemd OnCalendar schedule for the cassettes and the push.
# @param cassette_dir
#   Where cassettes write their findings files and Soundwave reads them.
# @param cassette_group
#   Group owning the cassette directory, for a cassette that runs outside
#   Soundwave's own service as an unprivileged user. Both shipped cassettes
#   run inside it as root, so neither needs this.
# @param openvas_cassette
#   Run the openvas (Greenbone) cassette before each push.
# @param vuls_cassette
#   Run the vuls cassette before each push.
# @param vuls_results_dir
#   Where the vuls module keeps its runs.
# @param vuls_complete_file
#   The file the vuls module writes the last complete run's path into. The
#   cassette reads only that run, never the newest directory, which may be a
#   scan still in progress.
# @param vuls_config
#   The vuls module's config.toml, for the hosts it expected to scan.
# @param vuls_windows_config
#   The vuls module's windows.json, for the Windows hosts it expected.
# @param vuls_database
#   The Vuls database, whose age is the cassette's feed time.
# @param findings_api_host
#   Host running a findings API, for the author's own consumer, whose API isn't
#   published. Unset disables the push, which is the default. Set, Soundwave
#   sends each cassette there unmerged as well as pushing to VR. It
#   authenticates with this node's Puppet agent certificate.
# @param findings_api_port
#   Port for that API.
# @param correlate
#   Report what correlation would join, without joining anything. Findings from
#   every cassette are grouped by certname, CVE, subject and fix type, and the
#   counts plus a bounded sample go to the log and the metrics file. Nothing
#   downstream changes: VR still gets a row per finding and a findings API
#   still gets each cassette verbatim. Off by default, because the count is worth having
#   before the merge is.
# @param compose_findings
#   Act on correlation rather than only report it. Findings that
#   share a correlation group are composed into one record: VR gets one row per
#   weakness across both cassettes, carrying every check's CVEs, the highest
#   per-CVE score, and a sentence naming the checks it came from. A findings API
#   stays one cassette per push and gets sets composed within a cassette only, with
#   each member's own values in `contributors`. A set over 5 findings or 10 CVEs
#   is left alone and counted, so one wide advisory cannot chain unrelated
#   findings together. Off by default: it changes what the VR console shows.
#   The correlation_exceptions below apply here too.
# @param correlation_exceptions
#   Check-ID pairs that must never be correlated, as `a|b,c|d`. For pairs the
#   key provably cannot separate: the SSH protocol check and the OpenSSH
#   version check both report CVE-2023-48795 on port 22 with the same fix type,
#   and one is closed by upgrading a package while the other is closed by
#   disabling algorithms. Seeded from what the sample turns up.
# @param min_confidence
#   QoD floor applied when mapping the merged findings to VR. Cassettes record
#   every finding with its confidence; VR has nowhere to put one, so a
#   low-confidence finding there reads the same as a certain one. 70 is gvmd's
#   own default and keeps PE showing exactly what it showed before.
# @param host_map_file
#   JSON object mapping each scanned address to its Puppet certname. Hosts found
#   in it are sent to PE under their certname; anything else keeps the name gvmd
#   had and is recorded in the cassette's unmapped list. With the openvas
#   cassette on it defaults to the openvas module's `scan-hosts.json`, beside
#   `compose_file`.
# @param metrics_file
#   If set, each run writes a node_exporter textfile here: when it ran, whether
#   it worked, PE's HTTP status, and per cassette its age, findings, host
#   states and what its filters dropped. Point it into the textfile collector's
#   directory.
# @param post_body_filepath
#   If set, the JSON body of the PE request is written here for debugging.
# @param transformer_name
#   Display name registered with PE.
# @param transformer_description
#   Description registered with PE.
#
# @example Basic usage via Hiera
#   include soundwave
#
class soundwave (
  Sensitive[String[1]] $pe_token,
  Optional[String[1]] $gmp_username   = undef,
  String[1] $compose_file             = '/opt/greenbone-community-container/compose.yaml',
  String[1] $gmp_service              = 'gvm-tools',
  String[1] $gmp_socket_path          = '/run/gvmd/gvmd.sock',
  Optional[String[1]] $scan_name                     = undef,
  String[1] $docker_cmd               = 'docker',
  Integer[1] $gmp_timeout             = 300,
  Boolean $manage_python              = true,
  Boolean $run_in_venv                = true,
  Optional[String[1]] $python_version                = undef,
  String[1] $sync_schedule            = 'daily',
  Stdlib::Absolutepath $cassette_dir  = '/var/lib/soundwave/cassettes',
  String[1] $cassette_group           = 'root',
  Boolean $openvas_cassette           = true,
  Boolean $vuls_cassette              = false,
  Stdlib::Absolutepath $vuls_results_dir    = '/var/lib/vuls/results',
  Stdlib::Absolutepath $vuls_complete_file  = '/var/lib/vuls/last-complete-run',
  Stdlib::Absolutepath $vuls_config         = '/etc/vuls/config.toml',
  Stdlib::Absolutepath $vuls_windows_config = '/etc/vuls/windows.json',
  Stdlib::Absolutepath $vuls_database       = '/var/lib/vuls/vuls.db',
  Integer[0, 100] $min_confidence     = 70,
  Boolean $correlate                  = false,
  Boolean $compose_findings           = false,
  Optional[String[1]] $correlation_exceptions        = undef,
  Optional[Stdlib::Host] $findings_api_host          = undef,
  Stdlib::Port $findings_api_port     = 10051,
  Optional[Stdlib::Absolutepath] $post_body_filepath = undef,
  Optional[Stdlib::Absolutepath] $host_map_file      = undef,
  Optional[Stdlib::Absolutepath] $metrics_file       = undef,
  String[1] $transformer_name         = 'Soundwave',
  String[1] $transformer_description  = 'Soundwave: merged scanner findings',
  Optional[Stdlib::Host] $pe_host     = undef,
  Optional[Sensitive[String[1]]] $gmp_password = undef,
) {
  $_pe_host = pick_default($pe_host, $server_facts['servername'])
  if $_pe_host =~ Undef or $_pe_host == '' {
    fail('soundwave: no Puppet server compiled this catalogue, so set soundwave::pe_host to the PE primary')
  }
  # The openvas module creates this read-only user, so it is set once, there.
  $_gmp_username = pick($gmp_username, lookup('openvas::scan_observer_user', Optional[String[1]], 'first', undef), 'admin')
  $_gmp_password = $gmp_password.lest || {
    lookup('openvas::scan_observer_password', Optional[Sensitive[String[1]]], 'first', undef)
  }
  if $openvas_cassette and $_gmp_password =~ Undef {
    fail('soundwave: the openvas cassette reads Greenbone over GMP, so set soundwave::gmp_password, or turn openvas_cassette off')
  }
  # The openvas module writes this beside its compose file. Only the openvas
  # cassette has addresses to map.
  $_host_map_file = if $host_map_file =~ NotUndef or !$openvas_cassette {
    $host_map_file
  } else {
    "${dirname($compose_file)}/scan-hosts.json"
  }
  $install_path = '/opt/puppetlabs/soundwave'
  $gmp_config_file = "${install_path}/python/gvm-tools.conf"

  if $manage_python {
    if $python_version =~ Undef {
      if $facts['os']['family'] == 'RedHat' and $facts['os']['release']['major'] == '8' {
        $python_version_install_string = 'python39'
        $python_version_install = '3.9'
      } else {
        $python_version_install_string = '3'
        $python_version_install = 'system'
      }
    } else {
      $python_version_install_string = $python_version
      $python_version_install = 'system'
    }

    # EL8, EL9 and EL10 carry Python 3 and pip in their own repos, and
    # puppet-epel has no EL10 key, so EPEL would only break EL10.
    class { 'python':
      ensure              => 'present',
      manage_venv_package => true,
      venv                => 'present',
      version             => $python_version_install_string,
      use_epel            => false,
    }
  } else {
    $python_version_install = 'system'
  }

  # /opt/puppetlabs is provided by the agent install (and declared by the
  # puppet_agent module), so only manage our own subtree under it.
  file { [$install_path, "${install_path}/python"]:
    ensure => 'directory',
  }

  file { "${install_path}/python/src":
    ensure  => directory,
    recurse => remote,
    purge   => true,
    replace => true,
    source  => 'puppet:///modules/soundwave/python/src',
    require => File[$install_path],
  }

  file { "${install_path}/python/requirements.txt":
    source  => 'puppet:///modules/soundwave/python/requirements.txt',
    require => File["${install_path}/python/src"],
  }

  # Neither cassette owns the directory; a cassette run outside Soundwave's
  # service as another user is what cassette_group is for.
  file { ['/var/lib/soundwave', $cassette_dir]:
    ensure => directory,
    owner  => 'root',
    group  => $cassette_group,
    mode   => '0770',
  }

  if $run_in_venv {
    python::pyvenv { 'soundwave-env':
      ensure     => present,
      version    => $python_version_install,
      systempkgs => true,
      venv_dir   => "${install_path}/python/env",
      require    => Class['python'],
    }
    $python_path = "${install_path}/python/env/bin/python3"
    python::requirements { "${install_path}/python/requirements.txt":
      virtualenv => "${install_path}/python/env",
      require    => File["${install_path}/python/requirements.txt"],
    }
  } else {
    $python_path = '/usr/bin/python3'
    python::requirements { "${install_path}/python/requirements.txt":
      require => File["${install_path}/python/requirements.txt"],
    }
  }

  # [Install] is what lets systemd enable the timer. Without it the unit is
  # static: Puppet's active => true starts it, but after a reboot nothing does
  # until the next agent run.
  $_timer = @("EOT")
    [Timer]
    OnCalendar=${sync_schedule}
    Persistent=true
    Unit=soundwave.service

    [Install]
    WantedBy=timers.target
    | EOT

  # Each enabled cassette writes its file, then Soundwave merges every cassette
  # in the directory and pushes. The cassettes carry a leading -, so one that
  # fails leaves its previous file in place and the push still goes: a Vuls
  # problem must not hold back Greenbone's findings, or the other way round.
  # Staleness is per cassette, and its alert is what reports the failure.
  $_openvas_step = $openvas_cassette ? {
    true    => "ExecStart=-${python_path} ${install_path}/python/src/cassettes/openvas.py\n",
    default => '',
  }
  $_vuls_step = $vuls_cassette ? {
    true    => "ExecStart=-${python_path} ${install_path}/python/src/cassettes/vuls.py --results-dir=${vuls_results_dir} --complete-file=${vuls_complete_file} --config=${vuls_config} --windows-config=${vuls_windows_config} --database=${vuls_database} --out=${cassette_dir}/vuls.json\n",
    default => '',
  }
  $_service = @("EOT")
    [Service]
    Type=oneshot
    ${_openvas_step}${_vuls_step}ExecStart=${python_path} ${install_path}/python/src/soundwave.py
    | EOT

  systemd::timer { 'soundwave.timer':
    ensure          => present,
    service_unit    => 'soundwave.service',
    service_content => $_service,
    active          => true,
    enable          => true,
    timer_content   => $_timer,
    require         => [File[$install_path], File[$cassette_dir]],
  }

  # Both files hold secrets (the PE token, the GMP credentials), so root only.
  file { "${install_path}/python/config.ini":
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0600',
    content => epp('soundwave/config.epp',
      {
        'sync_schedule'           => $sync_schedule,
        'python_path'             => $python_path,
        'cert_name'               => $trusted['certname'],
        'pe_token'                => $pe_token,
        'pe_host'                 => $_pe_host,
        'transformer_id'          => fqdn_uuid($trusted['certname']),
        'transformer_name'        => $transformer_name,
        'transformer_description' => $transformer_description,
        'post_body_filepath'      => $post_body_filepath,
        'gmp_config_file'         => $gmp_config_file,
        'compose_file'            => $compose_file,
        'gmp_service'             => $gmp_service,
        'gmp_socket_path'         => $gmp_socket_path,
        'scan_name'               => $scan_name,
        'docker_cmd'              => $docker_cmd,
        'gmp_timeout'             => $gmp_timeout,
        'host_map_file'           => $_host_map_file,
        'metrics_file'            => $metrics_file,
        'cassette_dir'            => $cassette_dir,
        'min_confidence'          => $min_confidence,
        'correlate'               => $correlate,
        'compose_findings'        => $compose_findings,
        'correlation_exceptions'  => $correlation_exceptions,
        'findings_api_host'       => $findings_api_host,
        'findings_api_port'       => $findings_api_port,
    }).node_encrypt::secret,
    require => File[$install_path],
  }

  # gvm-cli reads its GMP credentials from this file, bind-mounted read-only
  # into the gvm-tools run, so the password never appears in a process argv.
  # gvm-tools parses it with an interpolating ConfigParser, so the template
  # writes a literal % as %%. Without the openvas cassette nothing reads it, so
  # any credentials an earlier run left are removed.
  if $openvas_cassette {
    file { $gmp_config_file:
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0600',
      content => epp('soundwave/gvm-tools.conf.epp',
        {
          'gmp_username' => $_gmp_username,
          'gmp_password' => $_gmp_password,
      }).node_encrypt::secret,
      require => File["${install_path}/python"],
    }
  } else {
    file { $gmp_config_file:
      ensure => absent,
    }
  }
}
